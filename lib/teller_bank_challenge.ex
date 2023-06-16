defmodule Teller do
  # Constants used throughout the module
  @url "https://test.teller.engineering"
  @api_key "HowManyGenServersDoesItTakeToCrackTheBank?"
  @user_agent "Teller Bank iOS 2.0"
  @device_id "FWE42ZYNXF2EPXM7"
  @app_json "application/json"
  @teller_mission "accepted!"

  # The basic login function that handles the login flow
  def basic_login(username, password) do
    # Initialize login and get headers
    headers = initialize_login(username, password)

    # Print headers for debugging
    IO.inspect(headers)

    # Prepare otp body and send otp request
    otp_body = get_otp_code_body()
    otp_response = otp_request(otp_body, headers)

    # Extract account_id from otp response
    [%{"id" => account_id} | _] = otp_response.body["data"]["accounts"]["checking"]

    # Get account balance and update headers
    balance_response = account_balance(account_id, headers)
    details_header = update_headers(headers, balance_response.headers , username)

    # Print updated headers for debugging
    IO.inspect(details_header)

    # Get account details and handle encryption
    account_details(account_id, username, details_header)
    IO.inspect(handle_encryption(account_details(account_id, username, details_header), otp_response, username))

    # Return account details
    account_details(account_id, username, details_header)
  end

  # Function to get account balance
  def account_balance(account_id, headers) do
    balance_response = balance_request(account_id, headers)
    IO.inspect(balance_response)
  end

  # Function to get account details
  def account_details(account_id, username, headers) do
    details_response = details_request(account_id, headers)
    IO.inspect(details_response)
  end

  # Function to initialize login process
  def initialize_login(username, password) do
    base_headers = get_base_headers()
    signin_response = signin_request(username, password, base_headers)
    mfa_body = get_sms_body(signin_response.body["data"])
    mfa_headers = update_headers(base_headers, signin_response.headers, username)
    mfa_response = mfa_request(mfa_body, mfa_headers)
    mfa_login_headers = update_headers(base_headers, mfa_response.headers, username)
    mfa_login_headers
  end

  # Function to generate basic headers
  defp get_base_headers do
    [
      user_agent: @user_agent,
      api_key: @api_key,
      device_id: @device_id,
      content_type: @app_json,
      accept: @app_json,
      teller_mission: @teller_mission
    ]
  end

  # Function to send signin request
  defp signin_request(username, password, base_headers) do
    body = get_login_body(username, password)
    Req.post!("#{@url}/signin", body: body, headers: base_headers)
  end

  # Function to send multi-factor authentication request
  defp mfa_request(mfa_body, mfa_headers) do
    Req.post!("#{@url}/signin/mfa", body: mfa_body, headers: mfa_headers)
  end

  # Function to send OTP request
  defp otp_request(otp_body, mfa_headers) do
    Req.post!("#{@url}/signin/mfa/verify", body: otp_body, headers: mfa_headers)
  end

    # Function to send balance request
    defp balance_request(account_id, mfa_headers) do
      Req.get!("#{@url}/accounts/#{account_id}/balances", headers: mfa_headers)
    end

    # Function to send details request
    defp details_request(account_id, details_headers) do
      Req.get!("#{@url}/accounts/#{account_id}/details", headers: details_headers)
    end

    # Function to handle encryption of account details response
    defp handle_encryption(details_response, otp_response, username) do
      [ct,iv,t] = String.split(details_response.body["number"], ":")
      ct_base = Base.decode64!(ct)
      iv_base = Base.decode64!(iv)
      t_base = Base.decode64!(t)

      enc_key = otp_response.body["data"]["enc_key"]
      a_token = otp_response.body["data"]["a_token"]
      decoded = enc_key
      |>Base.decode64!()
      |>Jason.decode!()

      key = decoded["key"]

      # Encryption using AES 256 GCM
      encrypted_data = :crypto.crypto_one_time_aead(:aes_256_gcm, Base.decode64!(key), iv_base, ct_base, username, t_base, false)

      IO.inspect(encrypted_data)
    end

    # Function to generate body for login request
    defp get_login_body(username, password) do
      %{
        username: username,
        password: password
      }
      |> Jason.encode!()
    end

    # Function to generate body for sms request
    defp get_sms_body(signin_body) do
      [%{"id" => sms_id} | _] = signin_body["devices"]

      %{
        "device_id" => sms_id
      }
      |> Jason.encode!()
    end

    # Function to generate body for OTP code request
    defp get_otp_code_body() do
      %{
        "code" => "123456"
      }
      |> Jason.encode!()
    end

    # Function to update headers with new tokens
    def update_headers(base_headers, new_headers, username) do
      f_token = get_f_token(new_headers, username)
      request_token = get_request_token(new_headers)

      base_headers
      |> Keyword.put(:r_token, request_token)
      |> Keyword.put(:f_token, f_token)
    end

    # Function to generate f_token
    defp get_f_token(resp_headers, username) do
      f_spec =
        get_f_spec(resp_headers)
        |> Base.decode64!()
        {split_strings, separator} = SeparatorFinder.find_keys_within_brackets(f_spec)
        req_id = get_req_id(resp_headers)
        f_token_string = get_f_token_string(separator, Enum.reverse(split_strings), username, req_id)
        :crypto.hash(:sha256, f_token_string)
        |> Base.encode64()
        |> String.trim_trailing("=")
    end

    # Function to generate f_token string
    defp get_f_token_string(sep, f_values, username, req_id) do
      Enum.reduce(f_values, "", fn v, acc ->
        get_f_value(v, username, req_id) <> sep <> acc
      end)
      |> String.trim_trailing(sep)
    end

    # Function to get value for each f_spec
    defp get_f_value(v, username, req_id) do
      case v do
        "device-id" -> @device_id
        "api-key" -> @api_key
        "username" -> username
        "last-request-id" -> req_id
      end
    end

    # Function to get request id from response headers
    defp get_req_id(resp_headers) do
      Map.new(resp_headers)["f-request-id"]
    end

    # Function to get request token from response headers
    defp get_request_token(resp_headers) do
      Map.new(resp_headers)["r-token"]
    end

    # Function to get f-token specification from response headers
    defp get_f_spec(resp_headers) do
      Map.new(resp_headers)["f-token-spec"]
    end
  end

  defmodule SeparatorFinder do
    # Function to find keys and separator within brackets from a given string
    def find_keys_within_brackets(string) do
      keys = extract_keys_within_brackets(string)
      String.trim_leading(keys)
      |> String.trim_trailing(")")
      |> split_keys_and_separator
    end

    # Function to extract keys within brackets
    defp extract_keys_within_brackets(string) do
      ~r/\((.*?)\)/
      |> Regex.scan(string)
      |> Enum.map(&List.first(&1))
      |> Enum.join
    end

    # Function to split the string into keys and separator
    defp split_keys_and_separator(string) do
      special_character_regex = ~r/(?:[^-\p{L}]+|--)/
      separator_regex = ~r/(?:[^-\p{L}(]+|--)/
      split_strings = String.split(string, special_character_regex, trim: true)
      separator = List.first(Regex.run(separator_regex, string))

      {split_strings, separator}
    end
  end
