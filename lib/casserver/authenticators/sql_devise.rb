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
    read_standard_credentials(credentials)
    raise_if_not_configured

    user_model = self.class.user_model

    username_column = @options[:username_column] || "login"
    password_column = @options[:password_column] || "crypted_password"
    pepper   = @options[:pepper]||''

    log_connection_pool_size
    results = user_model.find(:all, :conditions => ["#{username_column} = ?", @username])
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
