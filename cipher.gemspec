require_relative 'lib/cipher/version'

Gem::Specification.new do |spec|
  spec.name          = "cipher"
  spec.version       = Cipher::VERSION
  spec.authors       = ["Panagiotis Matsinopoulos"]
  spec.email         = ["panagiotis@matsinopoulos.gr"]

  spec.summary       = %q{Two-way Encryption}
  spec.description   = %q{API to encrypt and decrypt a text}
  spec.homepage      = 'https://github.com/lavanda-uk/cipher'
  spec.license       = 'MIT'
  spec.required_ruby_version = Gem::Requirement.new('>= 2.3.0')

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/lavanda-uk/cipher'
  spec.metadata['changelog_uri'] = 'https://github.com/lavanda-uk/cipher/CHANGE_LOG.md'

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']
end