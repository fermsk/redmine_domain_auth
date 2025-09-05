module RedmineDomainAuth
  module AccountControllerPatch
    def self.included(base)
      base.send(:include, InstanceMethods)
      base.class_eval do
        prepend InstanceMethods
        skip_before_action :verify_authenticity_token, only: [:login]
        before_action :check_kerberos_auth, only: [:login]
      end
    end

    module InstanceMethods
      def check_kerberos_auth
        return true if User.current.logged?

        logger.info "=== Kerberos Auth Debug ==="
        logger.info "Headers: #{request.env.select { |k, v| k.start_with?('HTTP_') || k == 'REMOTE_USER' }}"
        
        kerberos_user = find_kerberos_user
        return unless kerberos_user.present?

        user = find_or_create_user(kerberos_user)
        
        if user&.active?
          logger.info "Successfully authenticated user: #{user.login}"
          successful_authentication(user)
          return false
        else
          logger.warn "Failed to authenticate or create user: #{kerberos_user}"
        end
      end

      private

      def find_kerberos_user
        remote_user = request.env['HTTP_X_FORWARDED_USER'] || 
                     request.env['REMOTE_USER'] ||
                     request.env['HTTP_REMOTE_USER']
        
        return nil unless remote_user.present?

        if Setting.plugin_redmine_domain_auth['strip_domain']
          remote_user = remote_user.split('@').first
        end
        
        remote_user.downcase
      end

      def find_or_create_user(login)
        user = User.find_by_login(login)
        return user if user.present?
        
        return nil unless Setting.plugin_redmine_domain_auth['auth_auto_create']
        
        create_domain_user(login)
      end

      def create_domain_user(login)
        auth_source = AuthSource.find_by_id(Setting.plugin_redmine_domain_auth['auth_source_ldap_id'])
        return nil unless auth_source

        begin
          # Get user info from LDAP
          attrs = auth_source.authenticate(login, '', true)
          return nil unless attrs

          # Create new user
          user = User.new
          user.login = login
          user.attributes = attrs
          
          # Set required attributes
          user.language = Setting.default_language
          user.auth_source_id = auth_source.id
          user.password = SecureRandom.hex(32)
          user.must_change_passwd = false
          
          if user.save
            add_to_default_group(user)
            logger.info "Created new domain user: #{login}"
            user
          else
            logger.error "Failed to create user: #{user.errors.full_messages.join(', ')}"
            nil
          end
        rescue => e
          logger.error "Error creating domain user: #{e.message}\n#{e.backtrace.join("\n")}"
          nil
        end
      end

      def add_to_default_group(user)
        group_id = Setting.plugin_redmine_domain_auth['default_group_id']
        if group_id.present?
          group = Group.find_by_id(group_id)
          if group
            group.users << user unless group.users.include?(user)
            logger.info "Added user #{user.login} to group #{group.name}"
          end
        end
      end
    end
  end
end

unless AccountController.included_modules.include?(RedmineDomainAuth::AccountControllerPatch)
  AccountController.send(:include, RedmineDomainAuth::AccountControllerPatch)
end