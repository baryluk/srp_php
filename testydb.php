<?
	try {
		$dbh = new PDO('mysql:host=localhost;dbname=srp', "root", "mpajz18",
		    array(PDO::ATTR_PERSISTENT => true));
		$dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$dbh->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);

		$dbh->beginTransaction();
		//$s1 = $dbh->prepare("insert into staff (id, first, last) values (?, ?, ?)");
		//$s1->execute(array(25, "Jon", "Bloggs"));
		//$s2 = $dbh->prepare("insert into salarychange (id, amount, changedate) values (?, ?, NOW())");
		//$s2->execute(array(25, 2100));
		$s3 = $dbh->prepare("SELECT * FROM dane");
		$s3->execute();
		$r = $s3->fetch();
		print_r($r);
		$r = $s3->fetch();
		print_r($r);
		$s3->closeCursor();
		$dbh->commit();

		$dbh = null;
	} catch (PDOException $e) {
		print "Error!: " . $e->getMessage() . "<br/>";
		die();
	} catch (Exception $e) {
		$dbh->rollBack();
		die();
	}
