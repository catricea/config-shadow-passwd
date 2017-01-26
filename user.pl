#/bin/usr/perl

use strict;
use warnings;
use utf8;
use Unicode::Normalize;

my %users;	
my $passwd = "passwd";
my $group = "group";
my $shadow = "shadow";
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
 	print "[fichier]\ntrie selon les informations présentes pour chaque enregistrement\najoute au système\n";
 	print "option -d [login]\nsupprime un utilisateur à partir de son login\n";
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

sub treatLogin {
	my $login = $_[0];
	$login = NFD($login);
	#suppression des espaces et caractères spéciaux
	$login =~ s/\s+//;
	$login =~ s/\pM//;
	$login =~ s/ë/e/;
	$login = lc($login);
	return ($login);
}

# trie les utilisateurs dans une table de hachage sur le nom de compte
sub sortUser {
	my $file = $ARGV[0];
	open(HANDLE, $file) or die ("impossible d'ouvrir le fichier\n");
	while(my $line = <HANDLE>) {
		my @fields = split(/;/, $line);
		chomp($fields[1]);
		chomp($fields[0]);
		#création du login
		my $login;
		# fields[1] = nom et fields[0] = prénom
		$login = substr($fields[1],0, length($fields[1])).substr($fields[0],0,1) if(length($fields[1]) <= 7);
		$login = substr($fields[1],0,7).substr($fields[0],0,1) if(length($fields[1]) > 7);
		#ajout de la clé et des champs
		$login = treatLogin($login);
		$users{$login} = generateID();
	}
	close(HANDLE);
}

# ajoute un seul utilisateur à partir de son prénom, son nom et son mot de passe
sub insertOneUser {
	my $firstName = $_[0];
	my $lastName = $_[1];
	my $oneMDP = $_[2];
	my $login;
	$login = substr($lastName,0, length($lastName)).substr($firstName,0,1) if(length($lastName) <= 7);
	$login = substr($lastName,0,7).substr($firstName,0,1) if(length($lastName) > 7);
	my $oneID = generateID();
	open(my $HAND2, '>', $passwd) or die ("impossible d'ouvrir le fichier passwd\n");
	print $HAND2 $login.":x:".$oneID.":50::/home/".$login.":bin/false\n";
	close($HAND2);
	open(my $HAND3, '>', $shadow) or die ("impossible d'ouvrir le fichier shadow\n");
	print $HAND3 $login.":".crypt($oneMDP, $salt).":0:9999:14:::\n";
	close($HAND3);
	`mkdir /home/$login`;
	print "insertion de l'utilisateur ".$login."\n";
}

# insère les utilisateurs dans le fichier /etc/passwd
# selon les données stockées dans la table de hachage users et la structure du fichier
sub insertPasswd {
	open(my $HAND2, '>', $passwd) or die ("impossible d'ouvrir le fichier passwd\n");
	foreach my $user(keys %users) {
		print $HAND2 $user.":x:".$users{$user}.":50::/home/".$user.":bin/false\n";
	}
	close($HAND2);
}

# insère les utilisateurs dans le fichier /etc/passwd
# selon les données stockées dans la table de hachage users et la structure du fichier
sub insertShadow {
open(my $HAND3, '>', $shadow) or die ("impossible d'ouvrir le fichier shadow\n");
	foreach my $user(keys %users) {
		print $HAND3 $user.":".crypt($mdp, $salt).":0:9999:14:::\n";
		`mkdir /home/$user`;
	}
	close($HAND3);
}

# insère les utilisateurs dans le fichier /etc/group
# ID du groupe de l'utilisateur par défaut : 50
sub insertGroup {
	open(my $HAND4, '>', $group) or die ("impossible d'ouvrir le fichier group\n");
	print $HAND4 "default:x:50:\n";
	close($HAND4);
}


sub removeUser {
	my $login = $_[0];
	#s/$login// $passwd;
	#s/$login// $shadow;
	print "suppression de l'utilisateur ".$login."\n";
}