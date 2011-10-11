<?php
/**
 * Secure Remote Password protocol for usage in JavaScript etc
 * Uses mysql for storage, easy to change
 * Needed extensions: mcrypt, mhash, gpm, bcmath, json, mysql
 */

error_reporting(E_ALL | E_STRICT);

// see rfc 5054
function Ng($size) {
	if ($size == 1024) {
		return array(
			"N"=>"EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
			"g"=>"2");
	}
/*2048, 
 2048-bit MODP Group

   This group is assigned id 14.
"FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"

  The generator is: 2.

4096-bit MODP Group
This group is assigned id 16.
  FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
      ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
      ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
      F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
      BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
      43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
      88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
      2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
      287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
      1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
      93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
      FFFFFFFF FFFFFFFF

   The generator is: 2.

   +--------+----------+---------------------+---------------------+
   | Group  | Modulus  | Strength Estimate 1 | Strength Estimate 2 |
   |        |          +----------+----------+----------+----------+
   |        |          |          | exponent |          | exponent |
   |        |          | in bits  | size     | in bits  | size     |
   +--------+----------+----------+----------+----------+----------+
   |   5    | 1536-bit |       90 |     180- |      120 |     240- |
   |  14    | 2048-bit |      110 |     220- |      160 |     320- |
   |  15    | 3072-bit |      130 |     260- |      210 |     420- |
   |  16    | 4096-bit |      150 |     300- |      240 |     480- |
   |  17    | 6144-bit |      170 |     340- |      270 |     540- |
   |  18    | 8192-bit |      190 |     380- |      310 |     620- |
   +--------+----------+---------------------+---------------------+
*/
	crit("unknown size");

}

// see rfc 5054
function pad($d) {
	return $d;
}

function crit($text) {
	die($text."\n");
	exit(1);
}

function H($text) {
	$ctx = hash_init("sha256");
	hash_update($ctx, $text);
	$r = hash_final($ctx, true);
	return $r;
}
function HM($text, $key) {
	return H($text.$key);
}

function get_random_bytes($c) {
	$fd = fopen('/dev/urandom', "rb");
	$d = fread($fd, $c);
	if (strlen($d) != $c) {
		crit("bad amount of random bytes readed");
	}
	fclose($fd);
	return $d;
}

function get_random_hex($c) {
	$s = "";
	while (strlen($s) < $c) {
		$s .= bin2hex(H(get_random_bytes(64)));
	}
	return $s;
}

function hex2bin($x) {
	return pack("H*", $x);
}

function gmp_bytes($x) {
	return hex2bin(gmp_strval($x, 16));
}

function mycon() {
	$link = mysql_connect("localhost", "root", "mpajz18");
	 if(!is_resource($link)) {
		crit("mysql connect");
	}
	if (!mysql_select_db("srp", $link)) {
		crit("mysql select");
	}
	return $link;
}

// dd if=/dev/random count=64 bs=1 | base64
$secret = "Q7d+U3bgZb02uqm/o22dIAuZ/MVFaO5vTDLb7CwXsCH/DwC9+sY3GoC+o/aKOqweiOK4wpzJC4AEJ3MmIZhn1g==";

$timeout = 12000;

// funkcja zapisuje podana tablice,
// szyfruje i podpisuje
function zapis($array) {
	global $secret;

	$plain = json_encode($array);


	$td = mcrypt_module_open('rijndael-256', '', 'ofb', '');
	$ks = mcrypt_enc_get_key_size($td);

	$key = substr(bin2hex(H($secret)), 0, $ks);

	$iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_DEV_RANDOM);

	mcrypt_generic_init($td, $key, $iv);
	$encrypted_base64 = base64_encode(mcrypt_generic($td, $plain));
	mcrypt_generic_deinit($td);
	mcrypt_module_close($td);

	$iv_base64 = base64_encode($iv);

	$sign = bin2hex(H($iv_base64.":".$key.":".$encrypted_base64));
	$a = array(
		"method" => "AES-256-OFB+SHA256",
		"iv_base64" => $iv_base64,
		"encrypted_base64" => $encrypted_base64,
		"sign" => $sign
	);

	return $a;
}

function wczytaj($d) {
	global $secret;

	if (!isset($d["iv_base64"])
		|| !isset($d["sign"])
		|| !isset($d["method"])
		|| !isset($d["encrypted_base64"])) {
		die("missing fields");
	}


	if ($d["method"] != "AES-256-OFB+SHA256") {
		die("bad method");
	}

	$td = mcrypt_module_open('rijndael-256', '', 'ofb', '');
	$ks = mcrypt_enc_get_key_size($td);

	$key = substr(bin2hex(H($secret)), 0, $ks);



	$encrypted_base64 = $d["encrypted_base64"];
	$iv_base64 = $d["iv_base64"];

	$sign = bin2hex(H($iv_base64.":".$key.":".$encrypted_base64));
	if ($sign != $d["sign"]) {
		crit("bad sign");
	}

	$iv = base64_decode($iv_base64);


	mcrypt_generic_init($td, $key, $iv);
	$plain = mdecrypt_generic($td, base64_decode($encrypted_base64));
	mcrypt_generic_deinit($td);
	mcrypt_module_close($td);

	return json_decode($plain, true);
}

function read_enc_state($enc_server_state, $phase) {
	global $timeout;

	if (!isset($enc_server_state) || $enc_server_state == NULL) {
		crit("enc_server_state missing");
	}
	$srow = wczytaj($enc_server_state);
	if ($srow == NULL) {
		crit("bad enc_server_state");
	}
	if (!isset($srow["phase"])) {
		crit("no phase in enc_server_state");
	}
	if ($srow["phase"] != $phase-1) {
		crit("bad phase in enc_server_state");
	}
	if (!isset($srow["time"])) {
		crit("no time in enc_server_state");
	}
	if ($srow["time"] > time()) {
		crit("bad time in enc_server_state");
	}
	if ($srow["time"]+$timeout < time()) {
		crit("timeout");
	}
	if (!isset($srow["I"])) {
		crit("no I in enc_server_state");
	}
	if ($srow["I"] == "") {
		crit("empty I in enc_server_state");
	}
	if ($phase == 1) {
		if ($srow["I"] != $_GET["I"]) {
			crit("I in enc_server_state and request are different");
		}
	}
	if (!isset($srow["N_base36"])
		|| !isset($srow["g_base36"])
		|| !isset($srow["k_base36"])
		|| !isset($srow["s_hex"])
		|| !isset($srow["v_base36"])) {
		crit("N_base36, g_base36, k_base36, s_hex or v_base36 missing in enc_server_state");
	}
	return $srow;
}


function srp() {
	global $timeout;

	$phase = "unknown";
	if (!isset($_GET["phase"])) {
		crit("phase parameter missing");
	} else {
		$phase = $_GET["phase"];
	}

	if ($phase == "0") { // create entry in db
		if (!isset($_GET["I"])) {
			crit("I missing");
		}
		if (!isset($_GET["P"])) {
			crit("P missing");
		}
		if (!isset($_GET["hash"])) {
			crit("hash missing");
		}
		if (!isset($_GET["N_size"])) {
			crit("N_size missing");
		}
		if (!isset($_GET["enc_client_state"])) {
			crit("enc_client_state missing");
		}
		$hash = $_GET["hash"];
		if ($hash != "SHA256") {
			crit("only SHA256 supported");
		}
		if ($_GET["N_size"] != "1024") {
			crit("only N_size 1024 supported");
		}
		$I = $_GET["I"];
		$P = $_GET["P"]; // secret, forget
		if (strlen($P) < 10) {
			crit("P too short");
		}

		$Ng = Ng(1024);

		//$N_bin = get_random_hex(64);
		//$N_hex = bin2hex($N_bin);
		$N_hex = $Ng["N"];
		$N_gmp = gmp_init($N_hex, 16);
		$N_base36 = gmp_strval($N_gmp, 36);

		//$g_bin = get_random_bytes(64);
		//$g_hex = bin2hex($g_bin);
		$g_hex = $Ng["g"];
		$g_gmp = gmp_init($g_hex, 16);
		$g_base36 = gmp_strval($g_gmp, 36);

		$k_bin = H(gmp_bytes($N_gmp).pad(gmp_bytes($g_gmp)));
		$k_hex = bin2hex($k_bin);
		$k_gmp = gmp_init($k_hex, 16);
		$k_base36 = gmp_strval($k_gmp, 36);

		//$s_bin = get_random_bytes(128);
		$s_bin = "\xBE\xB2\x53\x79\xD1\xA8\x58\x1E\xB5\xA7\x27\x67\x3A\x24\x41\xEE"; // example
		$s_hex = bin2hex($s_bin);

		$x_bin = H($s_bin.H($I.":".$P));
		$x_hex = bin2hex($x_bin);
		$x_gmp = gmp_init($x_hex, 16); // secret, forget
		$x_dec = gmp_strval($x_gmp);
		if (strlen($x_dec) < 32) {
			crit("x_dec too short");
		}

		$v_gmp = gmp_powm($g_gmp, $x_gmp, $N_gmp); // secret
		$v_dec = gmp_strval($v_gmp);
		if (strlen($v_dec) < 32) {
			crit("v_dec too short");
		}
		$v_base36 = gmp_strval($v_gmp, 36);
		// 7556AA045AEF2CDD07ABAF0F665C3E818913186F

		$srow = array();
		$srow["I"] = $I; // public
		$srow["s_hex"] = $s_hex; // public
		$srow["g_base36"] = $g_base36; // public
		$srow["N_base36"] = $N_base36; // public
		$srow["k_base36"] = $k_base36; // public, k nie trzeba zapisywac, bo wynika z N i g, ale tak szybciej
		$srow["v_base36"] = $v_base36; // pretty secret
		$srow["phase"] = 0;
		$srow["time"] = time();
		$enc_server_state = zapis($srow);
		$enc_server_state = "";

		$link = mycon();
		$I_escaped = mysql_real_escape_string($I, $link);

		if (strlen($I_escaped) >= 256
			|| strlen($hash) >= 32
			|| strlen($s_hex) >= 256
			|| strlen($g_base36) >= 1024
			|| strlen($N_base36) >= 1024
			|| strlen($v_base36) >= 1024
		) {
			crit("db will truncate field");
		}
		$q = sprintf("INSERT INTO dane (identity, hash, s_hex, g_base36, N_base36, v_base36) VALUES ('%s', '%s', '%s', '%s', '%s', '%s')",
			$I_escaped, $hash, $s_hex, $g_base36, $N_base36, $v_base36);
		$result = mysql_query($q, $link) or crit("Blad zapytania");
		echo mysql_error($link);
		if (mysql_affected_rows($link) == 0) {
			crit("User nie dopisany");
		}

		return array(
			"protocol" => "SRP-6a",
			"phase" => 0,
			"type" => "replay",
			"status" => "ok",
			"enc_client_state" => $_GET["enc_client_state"],
			"enc_server_state" => $enc_server_state
		);
	} else if ($phase == 1) {
		if (!isset($_GET["I"])) {
			crit("I missing");
		}
		if (!isset($_GET["hash"])) {
			crit("hash missing");
		}
		if (!isset($_GET["enc_client_state"])) {
			crit("enc_client_state missing");
		}
		if (!isset($_GET["enc_server_state"])) {
			crit("enc_server_state missing");
		}
		if ($_GET["hash"] != "SHA256") {
			crit("only SHA256 supported");
		}
		if ($_GET["enc_server_state"] != "") {
			crit("enc_server_state should be empty");
			//$srow = read_enc_state($_GET["enc_server_state"], 0);
		}

		$I = $_GET["I"];
		if (strlen($I) < 3) {
			crit("username (I) too short");
		}

		$link = mycon();
		$I_escaped = mysql_real_escape_string($I, $link);
		$q = sprintf("SELECT identity, hash, s_hex, g_base36, N_base36, v_base36 FROM dane WHERE identity = '%s'", $I_escaped);
		$result = mysql_query($q, $link) or crit("Blad zapytania");
		if (mysql_affected_rows($link) != 1) {
			crit("Should be 1, no such username");
		}
		if (mysql_num_rows($result) != 1) {
			crit("no such username");
		}

		$row_db = mysql_fetch_array($result);

		if ($row_db["hash"] != $_GET["hash"]) {
			crit("username exists, but different hash algo");
		}

		$srow = array();

		$srow["I"] = $I;

		$srow["s_hex"] = $row_db["s_hex"]; // public
		$srow["g_base36"] = $row_db["g_base36"]; // public
		$srow["N_base36"] = $row_db["N_base36"]; // public
		$srow["v_base36"] = $row_db["v_base36"]; // secret

		$g_gmp = gmp_init($srow["g_base36"], 36);
		$g_bin = gmp_bytes($g_gmp);

		$N_gmp = gmp_init($srow["N_base36"], 36);
		$N_bin = gmp_bytes($N_gmp);

		$k_hex = H($N_bin.pad($g_bin));
		$k_gmp = gmp_init($k_hex, 16);
		$srow["k_base36"] = gmp_strval($k_gmp, 36);

		$v_gmp = gmp_init($srow["v_base36"], 36); // secret

		$b_bin = get_random_bytes(128); // rfc 5054: at least 256 bit
		$b_hex = bin2hex($b_bin);
		$b_gmp = gmp_init($b_hex, 16);
		$b_base36 = gmp_strval($b_gmp, 36);
		$srow["b_base36"] = $b_base36; // secret (only server knowns)

		$B_gmp = gmp_mod(gmp_add(gmp_mul($k_gmp, $v_gmp), gmp_powm($g_gmp, $b_gmp, $N_gmp)), $N_gmp);
		// TODO: timming attack on powm
		$B_base36 = gmp_strval($B_gmp, 36);
		$srow["B_base36"] = $B_base36; // public

		$srow["phase"] = 1;
		$srow["time"] = time();

		$enc_server_state = zapis($srow);

		return array(
			"protocol" => "SRP-6a",
			"phase" => 1,
			"type" => "replay",
			"status" => "ok",
			"timeout" => $timeout,
			"enc_client_state" => $_GET["enc_client_state"],
			"hash" => $row_db["hash"],
			"s_hex" => $srow["s_hex"],
			"g_base36" => $srow["g_base36"],
			"N_base36" => $srow["N_base36"],
			"B_base36" => $B_base36,
			"enc_server_state" => $enc_server_state
		);
	} else if ($phase == 2) {
		// klient otrzymal, s, H, g, N, B
		// client oblicza x = H(s~H(I~P))
		// client generuje rendomowe a
		// client oblicza A=g^a, i nam wysyla
		// klient oblicza u = H(A~B)
		// klient oblicza S = (B - k*g^v)^(a+u*x)
		// klient oblicza M1 = H(A~B~S) i wysyla do serwera

		if (!isset($_GET["A_base36"])) {
			crit("A_base36 missing");
		}
		if (!isset($_GET["M1_hex"])) {
			crit("M1_hex missing");
		}
		if (!isset($_GET["enc_client_state"])) {
			crit("enc_client_state missing");
		}
		if (!isset($_GET["enc_server_state"])) {
			crit("enc_server_state missing");
		}

		$srow = read_enc_state($_GET["enc_server_state"], 2);

		$N_gmp = gmp_init($srow["N_base36"], 36);
		$g_gmp = gmp_init($srow["g_base36"], 36);
		$v_gmp = gmp_init($srow["v_base36"], 36);

		$b_gmp = gmp_init($srow["b_base36"], 36);

		$srow["A_base36"] = $_GET["A_base36"];
		$A_gmp = gmp_init($srow["A_base36"], 36); // public
		$A_bin = gmp_bytes($A_gmp);
		$A_hex = gmp_strval($A_gmp, 16); // debug

		$AN_gmp = gmp_mod($A_gmp, $N_gmp);
		if (gmp_cmp($AN_gmp, "0") == 0) {
			crit("A trivial");
		}

		$B_gmp = gmp_init($srow["B_base36"], 36);
		$B_bin = gmp_bytes($B_gmp);
		$B_hex = gmp_strval($B_gmp, 16); // debug

		$u_bin = H(pad($A_bin).pad($B_bin));
		$u_hex = bin2hex($u_bin);
		$u_gmp = gmp_init($u_hex, 16);
		// at least 32 bit, 32 is sufficient
		$srow["u_base36"] = gmp_strval($u_gmp, 36); // secret

		$S_gmp = gmp_powm(gmp_mod(gmp_mul($A_gmp, gmp_powm($v_gmp, $u_gmp, $N_gmp)), $N_gmp), $b_gmp, $N_gmp);
		// timing attack on powm
		$S_bin = gmp_bytes($S_gmp);
		$srow["S_base36"] = gmp_strval($S_gmp, 36); // secret
		$S_hex = gmp_strval($S_gmp, 16); // debug

		$M1_bin = H($A_bin.$B_bin.$S_bin);
		$M1_hex = bin2hex($M1_bin);

		if ($M1_hex != $_GET["M1_hex"]) {
			crit("M1 are different, probably bad password");
		}
		$M2_bin = H($A_bin.$M1_bin.$S_bin);
		$M2_hex = bin2hex($M2_bin);

		$K_bin = H($S_bin);
		$K_hex = bin2hex($K_bin);

		$srow["M1_hex"] = $M1_hex; // public
		$srow["M2_hex"] = $M2_hex; // public
		$srow["K_hex"] = $K_hex; // secret

		$srow["phase"] = 2;
		$srow["time"] = time();

		$enc_server_state = zapis($srow);
		return array(
			"protocol" => "SRP-6a",
			"phase" => 2,
			"type" => "replay",
			"status" => "ok",
			"timeout" => $timeout,
			"enc_server_state" => $enc_server_state,
			"enc_client_state" => $_GET["enc_client_state"],
			"M2_hex" => $srow["M2_hex"]
		);
	} else if ($phase == 3) {
		// klient oblicza M2 = H(A~M1~S)
		// klient potwierdza poprawnosc otrzymanego M2
		// klient oblicza K = H(S)
		// klient oblicza M = H( (H(N) xor H(g))~H(I)~s~A~B~K )
		if (!isset($_GET["M_hex"])) {
			crit("M_hex missing");
		}
		if (!isset($_GET['enc_client_state'])) {
			crit("enc_client_state missing");
		}
		if (!isset($_GET['enc_server_state'])) {
			crit("enc_server_state missing");
		}
		$srow = read_enc_state($_GET['enc_server_state'], 3);

		$N_gmp = gmp_init($srow["N_base36"], 36);
		$N_bin = gmp_bytes($N_gmp);
		$g_gmp = gmp_init($srow["g_base36"], 36);
		$g_bin = gmp_bytes($g_gmp);

		$A_gmp = gmp_init($srow["A_base36"], 36);
		$A_bin = gmp_bytes($A_gmp);

		$B_gmp = gmp_init($srow["B_base36"], 36);
		$B_bin = gmp_bytes($B_gmp);

		$s_bin = hex2bin($srow["s_hex"]);

		$I = $srow["I"];

		$K_hex = $srow["K_hex"];
		$K_bin = hex2bin($K_hex);

		$M_bin = HM((H($N_bin) ^ H($g_bin)).H($I).$s_bin.$A_bin.$B_bin, $K_bin);
		$M_hex = bin2hex($M_bin);
		if ($M_hex != $_GET["M_hex"]) {
			crit("M_hex are different");
		}
		$Z_bin = HM($A_bin.$M_bin, $K_bin);
		$Z_hex = bin2hex($Z_bin);

		$srow["M_hex"] = $M_hex; // public
		$srow["Z_hex"] = $Z_hex; // public

		$srow["phase"] = 3;
		$srow["time"] = time();

		$enc_server_state = zapis($srow);
		return array(
			"protocol" => "SRP-6a",
			"phase" => 3,
			"type" => "replay",
			"status" => "ok",
			"timeout" => $timeout,
			"enc_server_state" => $enc_server_state,
			"enc_client_state" => $_GET["enc_client_state"],
			"Z_hex" => $srow["Z_hex"],
		);
	} else {
		crit("unknown phase");
	}
}

function srp_test() {

$test_phase = 0;
//$I = "alice";
//$P = "password123";
$I = "aliceasd";
$P = "passasd98173";

if ($test_phase == 0) {
	$_GET = array(
		"protocol" => "SRP-6a",
		"type" => "request",
		"phase" => 0,
		"I" => $I,
		"P" => $P,
		"hash" => "SHA256",
		"N_size" => 1024,
		"enc_client_state" => ""
	);

	$json0 = json_encode(srp());
	echo "Rep0=", $json0, "\n\n";

	$json0 = json_decode($json0, true);
} else {
	$_GET = array(
		"protocol" => "SRP-6a",
		"type" => "request",
		"phase" => 1,
		"I" => $I,
		"hash" => "SHA256",
		"N_size" => 1024,
		"enc_server_state" => "",
		"enc_client_state" => ""
	);
	echo "Req1=", json_encode($_GET), "\n\n";

	$json = json_encode(srp());
	echo "Rep1=", $json, "\n\n";

	$json = json_decode($json, true);

	if (strlen($json["N_base36"]) < 100) {
		crit("client: N to small");
	}

	if (strlen($json["s_hex"]) < 32) {
		crit("client: s_hex to small");
	}

	$Ng_ok = false;
	if ($json["g_base36"] == "2" && $json["N_base36"] == "16xa82om033wnlk70asiomztdukuffhyjzvfan3p2mx73a3d7m9hws9a6bzc2ln42n93rmtrxi2p22g3xgxrvyryv9petn2256pdt281msxh9e812rhddxq4oo1f35sp7leese5d02obbwmiui7r2ddwfyqu31ctl4959pckt6lbolnlblhf4znrola2vk3wfto3e8z") {
		$Ng_ok = true;
	}
	if ($Ng_ok != true) {
		crit("client: Ng not whitelisted");
	}

	$N_gmp = gmp_init($json["N_base36"], 36);
	$N_bin = gmp_bytes($N_gmp);
	$g_gmp = gmp_init($json["g_base36"], 36);
	$g_bin = gmp_bytes($g_gmp);

	// check if N,g are secure: large, N is prime and g is primitive root, and discrate logarithm is hard
	// because chacking is hard to do in real-time, they should be whitelisted

	$k_hex = H($N_bin.pad($g_bin));
	$k_gmp = gmp_init($k_hex, 16);

	$s_hex = $json["s_hex"];
	$s_bin = hex2bin($s_hex);

	// client oblicza x = H(s~H(I~P))
	$x_bin = H($s_bin.H($I.":".$P));
	$x_hex = bin2hex($x_bin);
	$x_gmp = gmp_init($x_hex, 16); // secret

	$v_gmp = gmp_powm($g_gmp, $x_gmp, $N_gmp); // secret
	// timing attack

	// client generuje randomowe a
	$a_bin = get_random_bytes(128); // rfc 5054: at least 256 bit
	$a_hex = bin2hex($a_bin);
	$a_gmp = gmp_init($a_hex, 16); // secret

	// client oblicza A=g^a, i nam wysyla
	$A_gmp = gmp_powm($g_gmp, $a_gmp, $N_gmp); // public
	// timing attack
	$A_hex = gmp_strval($A_gmp, 16); // debug
	$A_bin = gmp_bytes($A_gmp);

	// ponieważ dostalismy B, możemy obliczyc juz S
	$B_gmp = gmp_init($json["B_base36"], 36);
	$B_hex = gmp_strval($B_gmp, 16); // debug
	$B_bin = gmp_bytes($B_gmp);

	// klient oblicza u = H(A~B)
	$u_bin = H(pad($A_bin).pad($B_bin));
	$u_hex = bin2hex($u_bin);
	$u_gmp = gmp_init($u_hex, 16);

	// klient oblicza S = (B - k*g^x)^(a+u*x)
	//$S_gmp = gmp_powm(gmp_sub($B_gmp, gmp_mul($k_gmp, gmp_powm($g_gmp, $v_gmp, $N_gmp))), gmp_add($a_gmp, gmp_mul($u_gmp, $x_gmp)), $N_gmp);
	$S_gmp = gmp_powm(gmp_mod(gmp_sub($B_gmp, gmp_mod(gmp_mul($k_gmp, $v_gmp), $N_gmp)), $N_gmp), gmp_add($a_gmp, gmp_mul($u_gmp, $x_gmp)), $N_gmp);
	// timing attack
	$S_bin = gmp_bytes($S_gmp);
	$S_hex = gmp_strval($S_gmp, 16); // secret

	// klient oblicza M1 = H(A~B~S) i wysyla do serwera
	$M1_bin = H($A_bin.$B_bin.$S_bin);
	$M1_hex = bin2hex($M1_bin);

	$_GET = array(
		"protocol" => "SRP-6a",
		"type" => "request",
		"phase" => 2,
		"A_base36" => gmp_strval($A_gmp, 36),
		"M1_hex" => $M1_hex,
		"enc_server_state" => $json["enc_server_state"],
		"enc_client_state" => ""
	);
	echo "Req2=", json_encode($_GET), "\n\n";

	$json2 = json_encode(srp());
	echo "Rep2=", $json2, "\n\n";

	$json2 = json_decode($json2, true);

		// klient oblicza M2 = H(A~M1~S)
		// klient potwierdza poprawnosc otrzymanego M2
		// klient oblicza K = H(S)
		// klient oblicza M = H( (H(N) xor H(g))~H(I)~s~A~B~K )
		$M2_bin = H($A_bin.$M1_bin.$S_bin);
		$M2_hex = bin2hex($M2_bin);
		if ($M2_hex != $json2["M2_hex"]) {
			crit("client: M2 are different, don't trust server!");
		}

		$K_bin = H($S_bin);
		$K_hex = bin2hex($K_bin); // secret

		$M_bin = HM((H($N_bin) ^ H($g_bin)).H($I).$s_bin.$A_bin.$B_bin, $K_bin);
		$M_hex = bin2hex($M_bin);

	$_GET = array(
		"protocol" => "SRP-6a",
		"type" => "request",
		"phase" => 3,
		"M_hex" => $M_hex,
		"enc_server_state" => $json2["enc_server_state"],
		"enc_client_state" => ""
	);
	echo "Req3=", json_encode($_GET), "\n\n";

	$json3 = json_encode(srp());
	echo "Rep3=", $json3, "\n\n";

	$json3 = json_decode($json3, true);

	$Z_bin = HM($A_bin.$M_bin, $K_bin);
	$Z_hex = bin2hex($Z_bin);
	if ($Z_hex != $json3["Z_hex"]) {
		crit("Z_hex different");
	}

	echo "Logged\n";
}
}

srp_test();

?>
