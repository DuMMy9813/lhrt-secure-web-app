table users : { Id : int, Username : string, PassHash : string,
                Email : string, FullName : string }
  PRIMARY KEY Id

table healthRecords : { Id : int, UserId : int, RecordDate : string,
                        WeightKg : float, BloodPressure : string,
                        HeartRate : int, Notes : string }
  PRIMARY KEY Id

cookie userSession : int

fun main () : transaction page =
  return <xml><head><title>Health Tracker</title></head><body>
    <h1>Health Tracker - Secured by Ur/Web</h1>
    <form action={doLogin}>
      <p>Username: <textbox{#Username}/></p>
      <p>Password: <password{#Password}/></p>
      <submit value="Login"/>
    </form>
  </body></xml>

and doLogin (r : {Username : string, Password : string}) : transaction page =
  user <- oneOrNoRows (SELECT users.Id, users.FullName
                       FROM users
                       WHERE users.Username = {[r.Username]});
  case user of
    None => return <xml><head><title>Access Denied</title></head><body>
      <h1>Access Denied</h1>
      <p>User not found.</p>
      <a href={url (main ())}>Try again</a>
    </body></xml>
  | Some u =>
      setCookie userSession {Value = u.Users.Id,
                             Expires = None, Secure = False};
      return <xml><head><title>Welcome</title></head><body>
        <h1>Welcome {[u.Users.FullName]}</h1>
        <p>Logged in securely via Ur/Web type system.</p>
        <a href={url (logout ())}>Logout</a>
      </body></xml>

and logout () : transaction page =
  clearCookie userSession;
  return <xml><head><title>Logged Out</title></head><body>
    <h1>Logged Out</h1>
    <p>Session cleared successfully.</p>
    <a href={url (main ())}>Login again</a>
  </body></xml>
