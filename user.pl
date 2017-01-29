#/bin/usr/perl

use strict;
use warnings;
use utf8;
use Unicode::Normalize;

my %users;	
my $passwd = "/etc/passwd";
my $group = "/etc/group";
my $shadow = "/etc/shadow";
my $log = "log";
my $mdp = "moi";
my $salt = "salt";
my $cptID = 1000;

use open ':encoding(utf8)';


# -----------------------gestion des paramètres----------------------------
if($#ARGV < 0) {
 	#Explique la commande
 	print "-n pour afficher l'aide\n";
 	exit 0;
}

if($ARGV[0] eq "-n") {
 	#Explique la commande
 	print "-----------\n";
 	print "[fichier]\ntrie selon les informations presentes pour chaque enregistrement\najoute au systeme\n";
 	print "-----------\n";
 	print "[nom] [prenom) [mot de passe]\najoute un utilisateur au systeme\n";
	print "-----------\n";
 	print "-d [login]\nsupprime un utilisateur a partir de son login\n";
 	print "-----------\n";
 	exit 0;
}

if(@ARGV == 3){
	insertOneUser($ARGV[0], $ARGV[1], $ARGV[2]);
}

if($ARGV[0] eq "-d" && @ARGV == 2) {
	removeUser($ARGV[1]);
}

my $lastID = `cat /etc/passwd | cut -d ':' -f3 | sort -n`;
my @ids = split(/\n/, $lastID);

if(-f $ARGV[0] && @ARGV == 1){
	sortUser();
	insertPasswd();
	insertShadow();
	insertGroup();
}

# génère un ID s'il ne se trouve pas déjà dans le fichier /etc/passwd
sub generateID {
	if(grep( /^$cptID$/, @ids)){
		$cptID ++;
	}
	push @ids, $cptID;
	return ($cptID);
}

#gère les caractères spéciaux et les espaces contenus dans le nom de compte
sub treatLogin {
	my $login = $_[0];
	$login = NFD($login);
	$login =~ s/\s+//;
	$login =~ s/\pM//;
	$login =~ s/ë/e/;
	$login = lc($login);
	return ($login);
}

# trie les utilisateurs dans une table de hachage sur le nom de compte
sub sortUser {
	my $file = $ARGV[0];
	open(my $HAND1, '>>', $log) or die ("impossible d'ouvrir le fichier log\n");
	print $HAND1 "prénom nom:login:uid:password\n";

	open(HANDLE, $file) or die ("impossible d'ouvrir le fichier\n");
	while(my $line = <HANDLE>) {
		my @fields = split(/;/, $line);
		chomp($fields[1]);
		chomp($fields[0]);

		#création du login
		my $login;
		$login = substr($fields[1],0, length($fields[1])).substr($fields[0],0,1) if(length($fields[1]) <= 7);
		$login = substr($fields[1],0,7).substr($fields[0],0,1) if(length($fields[1]) > 7);
		$login = treatLogin($login);
		$users{$login} = generateID();

		# ajout dans le fichier log
		print $HAND1 $fields[1]." ".$fields[0].":".$login.":".$users{$login}.":moi\n";
	}
	close(HANDLE);
}

# ajoute un seul utilisateur à partir de son prénom, son nom et son mot de passe
sub insertOneUser {
	my $firstName = $_[0];
	my $lastName = $_[1];
	my $oneMDP = $_[2];
	my $login;
	my $exist = 0;

	$login = substr($lastName,0, length($lastName)).substr($firstName,0,1) if(length($lastName) <= 7);
	$login = substr($lastName,0,7).substr($firstName,0,1) if(length($lastName) > 7);
	my $oneID = generateID();

	# vérifie l'existence de l'utilisateur
	open(HANDLE, $passwd) or die ("impossible d'ouvrir le fichier passwd\n");
	while(my $line = <HANDLE>) {
		if($line =~ /^$login/){
			$exist = 1;
		}
	}
	close(HANDLE);

	# écriture dans les fichiers
	if($exist == 0){
		# ajout du dossier
		`mkdir /home/$login` or die ("impossible de créer le répertoire\n");

		open(my $HAND2, '>>', $passwd) or die ("impossible d'ouvrir le fichier passwd\n");
		print $HAND2 $login.":x:".$oneID.":50::/home/".$login.":bin/bash\n";
		close($HAND2);

		open(my $HAND3, '>>', $shadow) or die ("impossible d'ouvrir le fichier shadow\n");
		print $HAND3 $login.":".crypt($oneMDP, $salt).":0:9999:14:::\n";
		close($HAND3);

		# ajout dans le fichier log
		open(my $HAND1, '>>', $log) or die ("impossible d'ouvrir le fichier log\n");
		print $HAND1 "prénom:nom:login:uid:password\n";
		print $HAND1 $firstName." ".$lastName.":".$login.":".$oneID.":".$oneMDP."\n";

		print "insertion de l'utilisateur ".$login."\n";
	}
}

# insère les utilisateurs dans le fichier /etc/passwd
# selon les données stockées dans la table de hachage users et la structure du fichier
sub insertPasswd {
	open(my $HAND2, '>>', $passwd) or die ("impossible d'ouvrir le fichier passwd\n");
	foreach my $user(keys %users) {
		`mkdir /home/$user`;# or die ("impossible de créer le répertoire\n");
		print $HAND2 $user.":x:".$users{$user}.":50::/home/".$user.":bin/bash\n";
	}
	close($HAND2);
}

# insère les utilisateurs dans le fichier /etc/passwd
# selon les données stockées dans la table de hachage users et la structure du fichier
sub insertShadow {
open(my $HAND3, '>>', $shadow) or die ("impossible d'ouvrir le fichier shadow\n");
	foreach my $user(keys %users) {
		print $HAND3 $user.":".crypt($mdp, $salt).":0:9999:14:::\n";
	}
	close($HAND3);
}

# insère les utilisateurs dans le fichier /etc/group
# ID du groupe de l'utilisateur par défaut : 50
sub insertGroup {

	# vérifie l'existence du groupe
	open(HANDLE, $group) or die ("impossible d'ouvrir le fichier group\n");
	my $exist = 0;
	while(my $line = <HANDLE>) {
		if($line =~ /50:$/) {
			$exist = 1;
		}
	}
	close (HANDLE);

	# écriture
	if($exist == 0){
		open(my $HAND4, '>>', $group) or die ("impossible d'ouvrir le fichier group\n");
		print $HAND4 "default:x:50:\n";
		close($HAND4);
	}
}

# retire un utilisateur en fonction de son nom de compte
sub removeUser {
	my $login = $_[0];
	`sed -i '/^$login/d' $passwd`;
	`sed -i '/^$login/d' $shadow`;
	`sed -i '/^$login/d' $group`;
	`sed -i '/$login/d' $log`;
	print "suppression de l'utilisateur ".$login."\n";
}