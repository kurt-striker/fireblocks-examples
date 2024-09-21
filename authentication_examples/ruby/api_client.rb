require 'jwt'
require 'openssl'
require 'digest'
require 'rest-client'
require 'securerandom'
require 'json'

class ApiTokenProvider
  def initialize(private_key_path, api_key, api_url)
    @private_key = OpenSSL::PKey::RSA.new(File.read(private_key_path))
    @api_key = api_key
    @api_url = api_url
  end

  def sign_jwt(path, body = nil)
    now = Time.now.to_i
    nonce = SecureRandom.uuid
    body_hash = Digest::SHA256.hexdigest(body || '')

    payload = {
      uri: path,
      nonce: nonce,
      iat: now,
      exp: now + 30,
      sub: @api_key,
      bodyHash: body_hash
    }

    headers = { alg: 'RS256', typ: 'JWT' }
    JWT.encode(payload, @private_key, 'RS256', headers)
  end

  def get_request(path)
    token = sign_jwt(path)

    headers = {
      Authorization: "Bearer #{token}",
      'X-API-Key' => @api_key
    }

    response = RestClient.get("#{@api_url}#{path}", headers)
    response.body
  rescue RestClient::ExceptionWithResponse => e
    e.response
  end

  def post_request(path, body)
    token = sign_jwt(path, body)

    headers = {
      Authorization: "Bearer #{token}",
      'X-API-Key' => @api_key,
      content_type: :json,
      accept: :json
    }

    response = RestClient.post("#{@api_url}#{path}", body, headers)
    response.body
  rescue RestClient::ExceptionWithResponse => e
    e.response
  end
end


if __FILE__ == $0
  api_key = 'MY_API_KEY'
  private_key_path = './fireblocks_secret_new.key'
  api_url = 'https://api.fireblocks.io' # Or 'https://sandbox-api.fireblocks.io'

  provider = ApiTokenProvider.new(private_key_path, api_key, api_url)

  # Example GET request
  get_response = provider.get_request('/v1/vault/accounts_paged')
  puts "GET Response: #{get_response}"

  # Example POST request
  body = {
    name: 'MyRubyVault',
    hiddenOnUI: false
  }.to_json

  post_response = provider.post_request('/v1/vault/accounts', body)
  puts "POST Response: #{post_response}"
end
