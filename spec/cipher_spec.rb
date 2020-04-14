# frozen_string_literal: true

require 'securerandom'

RSpec.describe Cipher do
  let(:clear_text) { 'foo bar' }

  let(:cipher_util) { described_class }

  let(:cipher_digest_key) { SecureRandom.hex }

  it 'has a version number' do
    expect(Cipher::VERSION).not_to be nil
  end

  it 'encrypts and decrypts a clear text' do
    iv, result = cipher_util.encrypt(clear_text, cipher_digest_key)

    expect(cipher_util.decrypt(result, iv, cipher_digest_key)).to eq(clear_text)
  end
end
