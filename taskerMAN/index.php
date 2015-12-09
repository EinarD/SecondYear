<?php
require_once "/includes/includes.php";
require_once "/includes/functions.php"

$emailreg = "";
$passreg = "";
$firstname = "";
$surname = "";
$emailsign = "";
$passsign = "";

if (isset($_SESSION["managerID"])) {
	smartRedirect("feed.php");
}

if (isset($_POST["register"])) {
	$emailreg =  $_POST["emailreg"];
	$firstname = $_POST["firstname"];
	$surname = 	 $_POST["surname"];
	$passreg = 	 $_POST["passreg"];
	
	if ((filter_var($emailreg, FILTER_VALIDATE_EMAIL))!==false  && preg_match("[a-zA-Z- ]",$firstname)!==false &&
	preg_match("[a-zA-Z- ]",$surname)!==false && strlen($passreg)>=5 && preg_match("[a-zA-Z0-9@#$%^&*_-!?<>]",$passreg)!==false) {
		$filtemailreg  = pg_escape_literal($emailreg);
		$filtfirstname = pg_escape_literal($firstname);
		$filtsurname   = pg_escape_literal($surname);
		$filtpassreg   = pg_escape_literal(password_hash($passreg,PASSWORD_DEFAULT));
	
		$select = pg_query($db, "SELECT email FROM managers where email={$filtemailreg}");
		if (!$select) {
			echo "An error occurred with the database.\n"; 
		}

		if($row = pg_fetch_row($select)) {
			echo "User with that email already exists, please try another\n";
		} else {
			$insert = pg_query($db, "INSERT into managers (email,firstname,surname,password) 
			VALUES ({$filtemailreg},{$filtfirstname},{$filtsurname},{$filtpassreg}) RETURNING id");
			if (!$insert) {
				echo "An error occurred with the database.\n"; 
			} else {
				$insrow = pg_fetch_row($insert);
				$_SESSION["managerID"] = $insrow[0];
				smartRedirect("feed.php");
			}	
		}
	}
	else {
		echo "One or more of your inputs were incorrect!\n";
	}
}

if (isset($_POST["signin"])) {
	$emailsign =  $_POST["emailsign"];
	$passsign  =  $_POST["passsign"];
	
	if ((filter_var($emailsign, FILTER_VALIDATE_EMAIL))!==false && preg_match("[a-zA-Z0-9@#$%^&*_-!?<>]",$passsign)!==false) {
		$filtemailsign  = pg_escape_literal($emailsign);
		
		$select = pg_query($db, "SELECT id,email,password FROM managers where email={$filtemailsign}");
		if (!$select) {
			echo "An error occurred with the database.\n"; 
		}

		if($row = pg_fetch_row($select)) {
			if (password_verify($passsign,$row[2])!==false) {
				$_SESSION["managerID"] = $row[0];
				smartRedirect("feed.php");
			} else {
				echo "Wrong password of manager!\n";
			}
		} else {
			echo "No manager with such name exists!\n";
		}	
	}
	else {
		echo "One or more of your inputs were incorrect!\n";
	}
}
pg_close($db);
?>
<html>
<head>
</head>
<body>
	<form id="signin" method="post"> 
			<input required pattern="[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" value="<?php echo $emailsign; ?>" placeholder="Email Address" type="text" name="emailsign" size="40" maxlength="100"><br> 
            <input required pattern="[a-zA-Z0-9@#$%^&*_-!?<>]*" value="<?php echo $passsign; ?>" placeholder="Password" type="password" name="passsign" size="40" maxlength="40"><br> 
            <input type="submit" name="signin" value="Sign in"> 
     </form> 
	 <br>
     <form id="register" method="post"> 
	        <input required pattern="[A-Z]+[a-zA-Z- ]*" value="<?php echo $firstname; ?>" type="text" name="firstname" size="20" maxlength="20" placeholder="First Name"><br> 
            <input required pattern="[A-Z]+[a-zA-Z- ]*" value="<?php echo $surname; ?>" type="text" name="surname" size="20" maxlength="40" placeholder="Surname"><br> 
			<input required pattern="[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" value="<?php echo $emailreg; ?>" type="text" name="emailreg" size="40" maxlength="100" placeholder="Email Address"><br> 
			<input required pattern="[a-zA-Z0-9@#$%^&*_-!?<>]*" value="<?php echo $passreg; ?>" type="password" name="passreg" size="40" maxlength="40" placeholder="Password" ><br> 
            <input type="submit" name="register" value="Register"> 
     </form> 
</body>
	
