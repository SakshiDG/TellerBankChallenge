defmodule BankApiWeb.ConnectController do
  use BankApiWeb, :controller

def connect(conn, %{"username" => username, "password" => password}) do
  case Teller.basic_login(username, password) do
    %Req.Response{status: status, headers: headers, body: result_body} ->
      IO.inspect(headers)
      json(conn, %{stats: OK})

    {:error, reason} ->
      IO.inspect(reason, label: "error response")
      # You might want to return an error response to the client here too
      json(conn, %{error: reason})

  end
end


end
