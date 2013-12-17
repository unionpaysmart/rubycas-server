require 'casserver/authenticators/sql'

begin
  require 'active_record'
rescue LoadError
  require 'rubygems'
  require 'active_record'
end

module BCrypt
end

if RUBY_PLATFORM == "java"
  require 'java'
else
  require "openssl"
end


begin
  RUBY_VERSION =~ /(\d+.\d+)/
  require "#{$1}/bcrypt_ext"
rescue LoadError
  require "bcrypt_ext"
end

require 'bcrypt/error'
require 'bcrypt/engine'
require 'bcrypt/password'


class CASServer::Authenticators::SQLDevise < CASServer::Authenticators::SQL

  def validate(credentials)
    email_name_regex  = '[\w\.%\+\-]+'.freeze
    domain_head_regex = '(?:[A-Z0-9\-]+\.)+'.freeze
    domain_tld_regex  = '(?:[A-Z]{2}|com|org|net|edu|gov|mil|biz|info|mobi|name|aero|jobs|museum)'.freeze
    email_regex       = /\A#{email_name_regex}@#{domain_head_regex}#{domain_tld_regex}\z/i

    read_standard_credentials(credentials)
    raise_if_not_configured

    user_model = self.class.user_model

    username_column = @options[:username_column] || "login"
    email_column = @options[:email_column]
    mobile_column = @options[:mobile_column]
    password_column = @options[:password_column] || "crypted_password"
    pepper   = @options[:pepper]||''

    log_connection_pool_size

    if  @username =~ /^\d{11}$/ && mobile_column.present?
      $LOG.info "Login with mobile:#{@username}"
      results = user_model.find(:all, :conditions => ["#{mobile_column} = ?", @username])
    elsif @username =~ email_regex && email_column.present?
      $LOG.info "Login with email:#{@username}"
      results = user_model.find(:all, :conditions => ["#{email_column} = ?", @username])
    else
      $LOG.info "Login with username:#{@username}"
      results = user_model.find(:all, :conditions => ["#{username_column} = ?", @username])
    end

    user_model.connection_pool.checkin(user_model.connection)

    if results.size > 0
      $LOG.warn("Multiple matches found for user '#{@username}'") if results.size > 1
      user = results.first
      crypted = user.send(password_column)
      $LOG.info("crypted password:#{crypted}")

      unless @options[:extra_attributes].blank?
        if results.size > 1
          $LOG.warn("#{self.class}: Unable to extract extra_attributes because multiple matches were found for #{@username.inspect}")
        else
          extract_extra(user)
          log_extra
        end
      end

      return false if crypted.blank?
      bcrypt   = ::BCrypt::Password.new(crypted)
      password = ::BCrypt::Engine.hash_secret("#{@password}#{pepper}", bcrypt.salt)
      return secure_compare(password, crypted)
    else
      $LOG.warn("Can't find any result")
      return false
    end
  end

  def secure_compare(a, b)
    return false if a.blank? || b.blank? || a.bytesize != b.bytesize
    l = a.unpack "C#{a.bytesize}"

    res = 0
    b.each_byte { |byte| res |= byte ^ l.shift }
    res == 0
  end
end
