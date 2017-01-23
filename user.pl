#/bin/usr/perl

use strict;
use warnings;

my %users;	
my $passwd = "passwd";
my $shadow = "shadow";
my $salt = "salt";

# gestion des paramètres
if($ARGV[0] eq "-n") {
 	#Explique la commande
 	print "paramètre : un fichier d'utilisateurs\ntrie selon les informations présentes pour chaque enregistrement\najoute au système\n";
 	exit 0;
}
die "prend en paramètre un fichier" if(! -f $ARGV[0] && $ARGV[0] ne "-n");

sortUser();
insertPasswd();
insertShadow();


# tri les utilisateurs dans une table de hachage sur le nom de compte
sub sortUser {
	my $file = $ARGV[0];
	open(HANDLE, $file) or die ("impossible d'ouvrir le fichier\n");
	while(my $line = <HANDLE>) {
		my @fields = split(/;/, $line);
		#supprime les retours à la ligne et les espaces inutiles
		chomp($fields[5]);
		#création du login
		my $login = substr($fields[0],0,7).substr($fields[1],0,1);
		#ajout des champs
		$users{$login} = \@fields; 
	}
	close(HANDLE);
}

# insère les utilisateurs dans le fichier /etc/passwd
# selon les données stockées dans la table de hachage users et la structure du fichier
sub insertPasswd {
	open(my $HAND2, '>', $passwd) or die ("impossible d'ouvrir le fichier passwd\n");
	foreach my $user(keys %users) {
		print $HAND2 $user.":x:".${$users{$user}}[3].":".${$users{$user}}[4].":".${$users{$user}}[5].":false\n";
	}
	close($HAND2);
}

# insère les utilisateurs dans le fichier /etc/passwd
# selon les données stockées dans la table de hachage users et la structure du fichier
sub insertShadow {
open(my $HAND3, '>', $shadow) or die ("impossible d'ouvrir le fichier shadow\n");
	foreach my $user(keys %users) {
		print $HAND3 $user.":".crypt(${$users{$user}}[2], $salt).":0:9999:14:::\n";
	}
	close($HAND3);
}