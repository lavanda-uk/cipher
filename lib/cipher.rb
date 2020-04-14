# frozen_string_literal: true

require 'openssl'
require 'base64'

require 'cipher/version'

module Cipher
  def self.digest_key(cipher_digest_key = nil)
    cipher_digest_key || ENV.fetch('CIPHER_DIGEST_KEY')
  end

  def self.encrypt(clear_text, cipher_digest_key)
    cipher = OpenSSL::Cipher::AES256.new :CBC
    cipher.encrypt

    iv = cipher.random_iv
    cipher.iv = iv

    digest_key = Cipher.digest_key(cipher_digest_key)
    hex_digest = Digest::SHA256.digest digest_key
    cipher.key = hex_digest

    clear_text = clear_text.to_json unless clear_text.is_a?(String)

    [Base64.strict_encode64(iv),
     Base64.strict_encode64(cipher.update(clear_text) + cipher.final)]
  end

  def self.decrypt(encrypted_text,initialization_vector, cipher_digest_key = nil)
    decipher = OpenSSL::Cipher::AES256.new :CBC
    decipher.decrypt

    decipher.iv = Base64.strict_decode64(initialization_vector)

    digest_key = Cipher.digest_key(cipher_digest_key)
    hex_digest = Digest::SHA256.digest digest_key
    decipher.key = hex_digest

    decipher.update(Base64.strict_decode64(encrypted_text)) + decipher.final
  end
end
