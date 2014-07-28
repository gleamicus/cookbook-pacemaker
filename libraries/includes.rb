# Common code used by Pacemaker LWRP providers

class Chef
  module Mixin::Pacemaker
    module StandardCIBObject
      def standard_create_action
        name = new_resource.name

        if @current_resource_definition.nil?
          create_resource(name)
        else
          maybe_modify_resource(name)
        end
      end

      # Instantiate @current_resource and read details about the existing
      # primitive (if any) via "crm configure show" into it, so that we
      # can compare it against the resource requested by the recipe, and
      # create / delete / modify as necessary.
      #
      # http://docs.opscode.com/lwrp_custom_provider_ruby.html#load-current-resource
      def standard_load_current_resource
        name = @new_resource.name

        cib_object = ::Pacemaker::CIBObject.from_name(name)
        unless cib_object
          ::Chef::Log.debug "CIB object definition nil or empty"
          return
        end

        unless cib_object.is_a? cib_object_class
          expected_type = cib_object_class.description
          ::Chef::Log.warn "CIB object '#{name}' was a #{cib_object.type} not a #{expected_type}"
          return
        end

        ::Chef::Log.debug "CIB object definition #{cib_object.definition}"
        @current_resource_definition = cib_object.definition
        cib_object.parse_definition

        @current_cib_object = cib_object
        init_current_resource
      end

      # In Pacemaker, target-role defaults to 'Started', but we want
      # to allow consumers of the LWRPs the choice whether their
      # newly created resource gets started or not, and we also want
      # to adhere to the Principle of Least Surprise.  Therefore we
      # stick to the intuitive semantics that
      #
      #   action :create
      #
      # creates the resource with target-role="Stopped" in order to
      # prevent it from starting immediately, whereas
      #
      #   action [:create, :start]
      #
      # creates the resource and then starts it.
      #
      # Consequently we deprecate setting target-role values directly
      # via the meta attribute.
      def deprecate_target_role
        if new_resource.respond_to? :meta
          meta = new_resource.meta
          if meta && meta['target-role']
            ::Chef::Log.warn "#{new_resource} used deprecated target-role " +
              "#{meta['target-role']}; use action :start / :stop instead"
          end
        end
      end

      def standard_create_resource
        deprecate_target_role

        cib_object = cib_object_class.from_chef_resource(new_resource)

        # We don't want resources to automatically start on creation;
        # only when the :create action is invoked.  However Pacemaker
        # defaults target-role to "Started", so we need to override it.
        if cib_object.respond_to? :meta # might be a constraint
          cib_object.meta['target-role'] = 'Stopped'
        end

        cmd = cib_object.configure_command

        ::Chef::Log.info "Creating new #{cib_object}"

        execute cmd do
          action :nothing
        end.run_action(:run)

        created_cib_object = ::Pacemaker::CIBObject.from_name(new_resource.name)

        raise "Failed to create #{cib_object}" if created_cib_object.nil?
        unless created_cib_object.exists?
          # This case seems pretty unlikely
          raise "Definition missing for #{created_cib_object} after creation"
        end

        new_resource.updated_by_last_action(true)
        ::Chef::Log.info "Successfully configured #{created_cib_object}"
      end

      def standard_delete_resource
        execute @current_cib_object.delete_command do
          action :nothing
        end.run_action(:run)
        new_resource.updated_by_last_action(true)
        Chef::Log.info "Deleted #{@current_cib_object}'."
      end
    end
  end
end
# require ::File.expand_path('standard_cib_object', File.dirname(__FILE__))

# Common code used by Pacemaker LWRP providers for resources supporting
# the :run action.

class Chef
  module Mixin::Pacemaker
    module RunnableResource
      include StandardCIBObject

      def start_runnable_resource
        name = new_resource.name
        unless @current_resource
          raise "Cannot start non-existent #{cib_object_class.description} '#{name}'"
        end
        return if @current_cib_object.running?
        execute @current_cib_object.crm_start_command do
          action :nothing
        end.run_action(:run)
        new_resource.updated_by_last_action(true)
        Chef::Log.info "Successfully started #{@current_cib_object}"
      end

      def stop_runnable_resource
        name = new_resource.name
        unless @current_resource
          raise "Cannot stop non-existent #{cib_object_class.description} '#{name}'"
        end
        return unless @current_cib_object.running?
        execute @current_cib_object.crm_stop_command do
          action :nothing
        end.run_action(:run)
        new_resource.updated_by_last_action(true)
        Chef::Log.info "Successfully stopped #{@current_cib_object}"
      end

      def delete_runnable_resource
        return unless @current_resource
        if @current_cib_object.running?
          raise "Cannot delete running #{@current_cib_object}"
        end
        standard_delete_resource
      end
    end
  end
end


require 'mixlib/shellout'

module Pacemaker
  class CIBObject
    attr_accessor :name, :definition

    @@subclasses = { } unless class_variable_defined?(:@@subclasses)

    class << self
      attr_reader :object_type

      def register_type(type_name)
        @object_type = type_name
        @@subclasses[type_name] = self
      end

      def get_definition(name)
        cmd = Mixlib::ShellOut.new("crm configure show #{name}")
        cmd.environment['HOME'] = ENV.fetch('HOME', '/root')
        cmd.run_command
        begin
          cmd.error!
          cmd.stdout
        rescue
          nil
        end
      end

      def definition_type(definition)
        unless definition =~ /\A(\w+)\s/
          raise "Couldn't extract CIB object type from '#{definition}'"
        end
        return $1
      end

      def from_name(name)
        definition = get_definition(name)
        return nil unless definition and ! definition.empty?
        from_definition(definition)
      end

      # Make sure this works on Ruby 1.8.7 which is missing
      # Object#singleton_class.
      def singleton_class
        class << self; self; end
      end

      def from_definition(definition)
        calling_class = self.singleton_class
        this_class = method(__method__).owner
        if calling_class == this_class
          # Invoked via (this) base class
          obj_type = definition_type(definition)
          subclass = @@subclasses[obj_type]
          unless subclass
            raise "No subclass of #{self.name} was registered with type '#{obj_type}'"
          end
          return subclass.from_definition(definition)
        else
          # Invoked via subclass
          obj = new(name)
          unless name == obj.name
            raise "Name '#{obj.name}' in definition didn't match name '#{name}' used for retrieval"
          end
          obj.definition = definition
          obj.parse_definition
          obj
        end
      end

      def from_chef_resource(resource)
        new(resource.name).copy_attrs_from_chef_resource(resource,
                                                         *attrs_to_copy_from_chef)
      end

      def attrs_to_copy_from_chef
        raise NotImplementedError, "#{self.class} didn't implement attrs_to_copy_from_chef"
      end
    end

    def initialize(name)
      @name = name
      @definition = nil
    end

    def copy_attrs_from_chef_resource(resource, *attrs)
      attrs.each do |attr|
        value = resource.send(attr.to_sym)
        writer = (attr + '=').to_sym
        send(writer, value)
      end
      self
    end

    def copy_attrs_to_chef_resource(resource, *attrs)
      attrs.each do |attr|
        value = send(attr.to_sym)
        writer = attr.to_sym
        resource.send(writer, value)
      end
    end

    def load_definition
      @definition = self.class.get_definition(name)

      if @definition and ! @definition.empty? and type != self.class.object_type
        raise CIBObject::TypeMismatch, \
          "Expected #{self.class.object_type} type but loaded definition was type #{type}"
      end
    end

    def parse_definition
      raise NotImplementedError, "#{self.class} must implement #parse_definition"
    end

    def exists?
      !! (definition && ! definition.empty?)
    end

    def type
      self.class.definition_type(definition)
    end

    def to_s
      "%s '%s'" % [self.class.description, name]
    end

    def definition_indent
      ' ' * 9
    end

    def continuation_line(text)
      " \\\n#{definition_indent}#{text}"
    end

    # Returns a single-quoted shell-escaped version of the definition
    # string, suitable for use in a command like:
    #
    #     echo '...' | crm configure load update -
    def quoted_definition_string
      "'%s'" % \
      definition_string \
        .gsub('\\') { '\\\\' } \
        .gsub("'")  { "\\'" }
    end

    def configure_command
      "crm configure " + definition_string
    end

    def reconfigure_command
      "echo #{quoted_definition_string} | crm configure load update -"
    end

    def delete_command
      "crm configure delete '#{name}'"
    end
  end

  class CIBObject::DefinitionParseError < StandardError
  end

  class CIBObject::TypeMismatch < StandardError
  end
end
require 'chef/mixin/shell_out'
# require File.expand_path('cib_object', File.dirname(__FILE__))

module Pacemaker
  class Resource < Pacemaker::CIBObject
    include Chef::Mixin::ShellOut

    def self.description
      type = self.to_s.split('::').last.downcase
      "#{type} resource"
    end

    def running?
      cmd = shell_out! "crm", "resource", "status", name
      Chef::Log.info cmd.stdout
      !! cmd.stdout.include?("resource #{name} is running")
    end

    def crm_start_command
      "crm --force resource start '#{name}'"
    end

    def crm_stop_command
      "crm --force resource stop '#{name}'"
    end

    # CIB object definitions look something like:
    #
    # primitive keystone ocf:openstack:keystone \
    #         params os_username="crowbar" os_password="crowbar" os_tenant_name="openstack" \
    #         meta target-role="Started" is-managed="true" \
    #         op monitor interval="10" timeout=30s \
    #         op start interval="10s" timeout="240" \
    #
    # This method extracts a Hash from one of the params / meta / op lines.
    def self.extract_hash(obj_definition, data_type)
      unless obj_definition =~ /\s+#{data_type} (.+?)\s*\\?$/
        return {}
      end

      h = {}
      Shellwords.split($1).each do |kvpair|
        break if kvpair == 'op'
        unless kvpair =~ /^(.+?)=(.*)$/
          raise "Couldn't understand '#{kvpair}' for '#{data_type}' section "\
            "of #{name} primitive (definition was [#{obj_definition}])"
        end
        h[$1] = $2.sub(/^"(.*)"$/, "\1")
      end
      h
    end
  end
end
# A mixin for Pacemaker::Resource subclasses which support meta attributes
# (priority, target-role, is-managed, etc.)

module Pacemaker
  module Mixins
    module Resource
      module Meta
        def self.included(base)
          base.extend ClassMethods
        end

        attr_accessor :meta

        def meta_string
          self.class.meta_string(meta)
        end

        module ClassMethods
          def meta_string(meta)
            return "" if ! meta or meta.empty?
            "meta " +
              meta.sort.map do |key, value|
              %'#{key}="#{value}"'
            end.join(' ')
          end
        end
      end
    end
  end
end
require 'shellwords'

this_dir = File.dirname(__FILE__)
# require File.expand_path('../resource', this_dir)
# require File.expand_path('../mixins/resource_meta', this_dir)

class Pacemaker::Resource::Primitive < Pacemaker::Resource
  TYPE = 'primitive'
  register_type TYPE

  include Pacemaker::Mixins::Resource::Meta

  attr_accessor :agent, :params, :op

  def initialize(*args)
    super(*args)

    @agent = nil
  end

  def self.attrs_to_copy_from_chef
    %w(agent params meta op)
  end

  def parse_definition
    unless definition =~ /\A#{self.class::TYPE} (\S+) (\S+)/
      raise Pacemaker::CIBObject::DefinitionParseError, \
        "Couldn't parse definition '#{definition}'"
    end
    self.name  = $1
    self.agent = $2

    %w(params meta).each do |data_type|
      hash = self.class.extract_hash(definition, data_type)
      writer = (data_type + '=').to_sym
      send(writer, hash)
    end

    self.op = {}
    %w(start stop monitor).each do |op|
      h = self.class.extract_hash(definition, "op #{op}")
      self.op[op] = h unless h.empty?
    end
  end

  def params_string
    self.class.params_string(params)
  end

  def op_string
    self.class.op_string(op)
  end

  def definition_string
    str = "#{self.class::TYPE} #{name} #{agent}"
    %w(params meta op).each do |data_type|
      unless send(data_type).empty?
        data_string = send("#{data_type}_string")
        str << continuation_line(data_string)
      end
    end
    str
  end

  def configure_command
    args = %w(crm configure primitive)
    args << [name, agent, params_string, meta_string, op_string]
    args.join " "
  end

  def self.params_string(params)
    return "" if ! params or params.empty?
    "params " +
    params.sort.map do |key, value|
      %'#{key}="#{value}"'
    end.join(' ')
  end

  def self.op_string(ops)
    return "" if ! ops or ops.empty?
    ops.sort.map do |op, attrs|
      attrs.empty? ? nil : "op #{op} " + \
      attrs.sort.map do |key, value|
        %'#{key}="#{value}"'
      end.join(' ')
    end.compact.join(' ')
  end

end
this_dir = File.dirname(__FILE__)
# require File.expand_path('../resource', this_dir)
# require File.expand_path('../mixins/resource_meta', this_dir)

class Pacemaker::Resource::Clone < Pacemaker::Resource
  TYPE = 'clone'
  register_type TYPE

  include Pacemaker::Mixins::Resource::Meta

  # FIXME: need to handle params as well as meta

  attr_accessor :rsc

  def self.attrs_to_copy_from_chef
    %w(rsc meta)
  end

  def definition_string
    str = "#{self.class::TYPE} #{name} #{rsc}"
    unless meta.empty?
      str << continuation_line(meta_string)
    end
    str
  end

  def parse_definition
    unless definition =~ /^#{self.class::TYPE} (\S+) (\S+)/
      raise Pacemaker::CIBObject::DefinitionParseError, \
        "Couldn't parse definition '#{definition}'"
    end
    self.name = $1
    self.rsc  = $2
    self.meta = self.class.extract_hash(definition, 'meta')
  end

end
# require File.expand_path('clone', File.dirname(__FILE__))

class Pacemaker::Resource::MasterSlave < Pacemaker::Resource::Clone
  TYPE = 'ms'
  register_type TYPE

  #include Pacemaker::Mixins::Resource::Meta

  attr_accessor :rsc
end
this_dir = File.dirname(__FILE__)
# require File.expand_path('../resource', this_dir)
# require File.expand_path('../mixins/resource_meta', this_dir)

class Pacemaker::Resource::Group < Pacemaker::Resource
  TYPE = 'group'
  register_type TYPE

  include Pacemaker::Mixins::Resource::Meta

  # FIXME: need to handle params as well as meta

  attr_accessor :members

  def self.attrs_to_copy_from_chef
    %w(members meta)
  end

  def parse_definition
    unless definition =~ /^#{self.class::TYPE} (\S+) (.+?)(\s+\\)?$/
      raise Pacemaker::CIBObject::DefinitionParseError, \
        "Couldn't parse definition '#{definition}'"
    end
    self.name    = $1
    members = $2.split
    trim_from = members.find_index('meta')
    members = members[0..trim_from-1] if trim_from
    self.members = members
    self.meta    = self.class.extract_hash(definition, 'meta')
  end

  def definition_string
    str = "#{self.class::TYPE} #{name} " + members.join(' ')
    unless meta.empty?
      str << continuation_line(meta_string)
    end
    str
  end

end
# require File.expand_path('cib_object', File.dirname(__FILE__))

module Pacemaker
  class Constraint < Pacemaker::CIBObject
    def self.description
      type = self.to_s.split('::').last
      "#{type} constraint"
    end
  end
end
# require File.expand_path('../constraint', File.dirname(__FILE__))

class Pacemaker::Constraint::Colocation < Pacemaker::Constraint
  TYPE = 'colocation'
  register_type TYPE

  attr_accessor :score, :resources

  def self.attrs_to_copy_from_chef
    %w(score resources)
  end

  def parse_definition
    # FIXME: this is incomplete.  It probably doesn't handle resource
    # sets correctly, and certainly doesn't handle node attributes.
    # See the crm(8) man page for the official BNF grammar.
    unless definition =~ /^#{self.class::TYPE} (\S+) (\d+|[-+]?inf): (.+?)\s*$/
      raise Pacemaker::CIBObject::DefinitionParseError, \
        "Couldn't parse definition '#{definition}'"
    end
    self.name  = $1
    self.score = $2
    self.resources = $3.split
  end

  def definition_string
    "#{self.class::TYPE} #{name} #{score}: " + resources.join(' ')
  end

end
# require ::File.expand_path('../../../pacemaker/cib_object',
                           # File.dirname(__FILE__))

