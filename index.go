package main

import "net/http"

const indexHTML = `
<!DOCTYPE html>
<html>
  <head>
    <script src="//code.jquery.com/jquery-1.11.2.min.js"></script>
  </head>
  <body>
    <h1>FIDO U2F Go Library Demo</h1>
		<div id="login-container">
			<label for="username"><b>Username</b></label>
			<input type="text" placeholder="Enter Username" name="username" id="username" required>

			<label for="password"><b>Password</b></label>
			<input type="password" placeholder="Enter Password" name="password" id="password" required>

			<button type="submit" id="login">Login</button>
		</div>
		<div id="logged-in">Logged in as <span id="username-show" />.</div>
    <ul>
      <li><a href="javascript:register();">Register token</a></li>
      <li><a href="javascript:sign();">Authenticate</a></li>
    </ul>
    <p>Open Chrome Developer Tools to see debug console logs.</p>
    <script>
	function checkStatus() {
	  $.getJSON('/status', function(data) {
		  $("#logged-in").hide();
		  if(data.Password) {
			  $("#username-show").text(data.Username);
			  $("#login-container").hide();
				$("#logged-in").show();
			}
		});
	}
	$(document).ready(function(){
		checkStatus();
		$("#login").click(function() {
			var username = $("#username").val();
			var password = $("#password").val();
			$.post('/passwordLogin', {username: username, password: password}).success(function (){
			  checkStatus();
			}).fail(serverError);
		});
	});
  function serverError(data) {
    console.log(data);
    alert('Server error code ' + data.status + ': ' + data.responseText);
  }
  function checkError(resp) {
    if (!('errorCode' in resp)) {
      return false;
    }
    if (resp.errorCode === 0) {
      return false;
    }
    var msg = 'U2F error code ' + resp.errorCode;
    if (resp.errorMessage) {
      msg += ': ' + resp.errorMessage;
    }
    console.log(msg);
    alert(msg);
    return true;
  }
  function u2fRegistered(resp) {
    console.log(resp);
    if (checkError(resp)) {
      return;
    }
    $.post('/registerResponse', JSON.stringify(resp)).success(function() {
      alert('Success');
    }).fail(serverError);
  }
  function register() {
    $.getJSON('/registerRequest').success(function(req) {
      console.log(req);
      u2f.register(req.appId, req.registerRequests, req.registeredKeys, u2fRegistered, 30);
    }).fail(serverError);
  }
  function u2fSigned(resp) {
    console.log(resp);
    if (checkError(resp)) {
      return;
    }
    $.post('/signResponse', JSON.stringify(resp)).success(function() {
      alert('Success');
    }).fail(serverError);
  }
  function sign() {
    $.getJSON('/signRequest').success(function(req) {
      console.log(req);
      u2f.sign(req.appId, req.challenge, req.registeredKeys, u2fSigned, 30);
    }).fail(serverError);
  }
    </script>
  </body>
</html>
`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(indexHTML))
}
