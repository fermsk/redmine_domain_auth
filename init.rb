require 'redmine'

Redmine::Plugin.register :redmine_domain_auth do
  name 'Kerberos Domain Authentication Plugin'
  author 'Ivan Zheleznyi'
  description 'Plugin for Kerberos authentication with auto user creation'
  version '1.0.1'
  url 'http://gitlab.aladdin.ru/devops/infrastructure/redmine_6/redmine_domain_auth.git'
  
  settings default: {
    'auth_auto_create' => true,
    'auth_source_ldap_id' => 1,
    'default_group_id' => nil,
    'domain_name' => 'ALADDIN.RU',
    'strip_domain' => true
  }, partial: 'settings/domain_auth_settings'
end

Rails.configuration.to_prepare do
  require_dependency 'redmine_domain_auth/account_controller_patch'
end