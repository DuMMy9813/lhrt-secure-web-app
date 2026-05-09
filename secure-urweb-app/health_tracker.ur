cookie userSession : string

fun doAddRecord
    (r : {RecordDate : string,
          WeightKg : string,
          BloodPressure : string,
          HeartRate : string,
          Notes : string}) : transaction page =
    return <xml>
      <body>
        <h1>Record Saved</h1>
        <p>Date: {[r.RecordDate]}</p>
        <p>Weight Kg: {[r.WeightKg]}</p>
        <p>Blood Pressure: {[r.BloodPressure]}</p>
        <p>Heart Rate: {[r.HeartRate]}</p>
        <p>Notes: {[r.Notes]}</p>
      </body>
    </xml>

fun doLogin (r : {Username : string, Password : string}) : transaction page =
    if r.Username = "admin" && r.Password = "admin123" then
        setCookie userSession {
            Value = r.Username,
            Expires = None,
            Secure = False
        };

        return <xml>
          <body>
            <h1>Dashboard</h1>
            <p>Welcome {[r.Username]}</p>

            <p>
              This is the Ur/Web translation of the PHP Health Tracker login workflow.
            </p>

            <h2>Add Health Record</h2>

            <form>
              <p>Date: <textbox{#RecordDate}/></p>
              <p>Weight Kg: <textbox{#WeightKg}/></p>
              <p>Blood Pressure: <textbox{#BloodPressure}/></p>
              <p>Heart Rate: <textbox{#HeartRate}/></p>
              <p>Notes: <textbox{#Notes}/></p>
              <submit action={doAddRecord} value="Save Record"/>
            </form>
          </body>
        </xml>
    else
        return <xml>
          <body>
            <h1>Login Failed</h1>
            <p>Invalid username or password.</p>
          </body>
        </xml>

fun main () : transaction page =
    return <xml>
      <body>
        <h1>Health Tracker</h1>

        <p>
          A lightweight Ur/Web translation of the PHP Health Tracker application.
        </p>

        <h2>Login</h2>

        <form>
          <p>Username: <textbox{#Username}/></p>
          <p>Password: <textbox{#Password}/></p>
          <submit action={doLogin} value="Login"/>
        </form>
      </body>
    </xml>
