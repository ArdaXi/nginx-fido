package main

import (
	"html/template"
	"net/http"
)

const loginHTML = `
<!DOCTYPE html>
<html>
  <head>
    <script src="//code.jquery.com/jquery-1.11.2.min.js"></script>
		<style>
			html {
				height: 100%
			}

			.login {
				background: #eceeee;
				border: 1px solid #42464b;
				border-radius: 6px;
				height: 257px;
				margin: 20px auto 0;
				width: 298px;
			}

			.login h1 {
				border-bottom: 1px solid #a6abaf;
				border-radius: 6px 6px 0 0;
				box-sizing: border-box;
				color: #727678;
				display: block;
				height: 43px;
				font: 600 14px/1 'Open Sans', sans-serif;
				padding-top: 14px;
				margin: 0;
				text-align: center;
				text-shadow: 0 -1px 0 rgba(0, 0, 0, 0.2), 0 1px 0 #fff;
			}

			input[type="password"],
			input[type="text"],
			.username {
				border: 1px solid #a1a3a3;
				border-radius: 4px;
				box-shadow: 0 1px #fff;
				box-sizing: border-box;
				color: #696969;
				height: 39px;
				margin: 31px 0 0 29px;
				padding-left: 37px;
				transition: box-shadow 0.3s;
				width: 240px;
			}

			input[type="password"]:focus,
			input[type="text"]:focus {
				box-shadow: 0 0 4px 1px rgba(55, 166, 155, 0.3);
				outline: 0;
			}

			.show-password {
				display: block;
				height: 16px;
				margin: 26px 0 0 28px;
				width: 87px;
			}

			.forgot {
				color: #7f7f7f;
				display: inline-block;
				float: right;
				font: 12px/1 sans-serif;
				left: -19px;
				position: relative;
				text-decoration: none;
				top: 5px;
				transition: color .4s;
			}

			.forgot:hover {
				color: #3b3b3b
			}

			input[type="submit"] {
				width: 240px;
				height: 35px;
				display: block;
				font-family: Arial, "Helvetica", sans-serif;
				font-size: 16px;
				font-weight: bold;
				color: #fff;
				text-decoration: none;
				text-transform: uppercase;
				text-align: center;
				text-shadow: 1px 1px 0px #37a69b;
				padding-top: 6px;
				margin: 29px 0 0 29px;
				position: relative;
				cursor: pointer;
				border: none;
				background-color: #37a69b;
				background-image: linear-gradient(top, #3db0a6, #3111);
				border-top-left-radius: 5px;
				border-top-right-radius: 5px;
				border-bottom-right-radius: 5px;
				border-bottom-left-radius: 5px;
				box-shadow: inset 0px 1px 0px #2ab7ec, 0px 5px 0px 0px #497a78, 0px 10px 5px #999;
			}

			input[type="submit"].disabled {
				text-shadow: 1px 1px 0px #c85964;
			  background-color: #c85964;
				background-image: linear-gradient(top, #c24f59, #ceee);
				box-shadow: inset 0px 1px 0px #d54813, 0px 2px 0px 0px #b68587, 0px 5px 3px #999;
			}

			.shadow {
				background: #000;
				border-radius: 12px 12px 4px 4px;
				box-shadow: 0 0 20px 10px #000;
				height: 12px;
				margin: 30px auto;
				opacity: 0.2;
				width: 270px;
			}

			input[type="submit"]:active {
				top: 3px;
				box-shadow: inset 0px 1px 0px #2ab7ec, 0px 2px 0px 0px #31524d, 0px 5px 3px #999;
			}

			input[type="submit"].disabled:active {
				box-shadow: inset 0px 1px 0px #d54813, 0px 2px 0px 0px #ceadb2, 0px 5px 3px #999;
			}
		</style>
  </head>
  <body>
		<form id="login-form" class="login" action="#" method="post">
			<input type="text" placeholder="Username" name="username" id="username" required>
			<input type="password" placeholder="Password" name="password" id="password" required>
			<input type="submit" id="login" value="Login">
		</form>
		<div class="login" id="logged-in">
			<input type="text" name="username" id="username-show" disabled>
			<input type="password" name="password-show" disabled>
			<input type="submit" id="logout" class="disabled" value="Logout">
		</div>
    <script>
	function checkStatus() {
	  $.getJSON('/status', function(data) {
		  $("#login-form").hide();
		  $("#logged-in").hide();
		  if(data.Password) {
			  $("#username-show").attr("value", data.Username);
			  $("#login-form").hide();
				$("#logged-in").show();
				sign();
			} else {
				$("#login-form").show(); 
			}
		});
	}
	$(document).ready(function(){
		checkStatus();
		$("#login-form").submit(function(event) {
			var username = $("#username").val();
			var password = $("#password").val();
			$.post('/passwordLogin', {username: username, password: password}).success(function (){
			  checkStatus();
			}).fail(serverError);
			event.preventDefault();
		});
		$("#logout").click(function() {
		  $.post('/logout').success(function (){
			  checkStatus();
			});
		})
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
  function u2fSigned(resp) {
    console.log(resp);
    if (checkError(resp)) {
      return;
    }
    $.post('/signResponse', JSON.stringify(resp)).success(function() {
		  {{if .}}window.location.replace("{{.}}");{{end}}
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

var loginTemplate = template.Must(template.New("login").Parse(loginHTML))

func loginHandler(w http.ResponseWriter, r *http.Request) {
	original := r.Header.Get("X-Original-URL")
	loginTemplate.Execute(w, original)
}
