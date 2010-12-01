#!/usr/bin/perl -w
use strict;
require "./SpamAssassin.pm";

# print "T::SA Version: " . $Text::SpamAssassin::VERSION . "\n\n";

my $junk = Text::SpamAssassin->new();
$junk->set_spamassassin_prefs( 'userprefs_filename',
	'/home/apthorpe/pjx/Text/SpamAssassin/comment_spam_prefs.cf');

my $comment = q{HOT TE</zoo>EN FA</paris>R</hilton>M ANIMALS refi<bogon>nan<dross>ce toner cartridges with CIALIS AND VIAGRA - <a href="http://test.surbl.org/">MAKE MONEY FAST!!!</a> $$$};

$junk->set_text($comment);
my %response = %{$junk->analyze()};
foreach my $kk (keys %response) {
	print $kk,": ",$response{$kk},"\n";
}

# print "===\n";
# print $junk->{"_mail"}->as_string, "\n";
print "===\n";
print $junk->{"_rfc822_message"}->as_string, "\n";
print $junk->{"_rfc822_message"}->body, "\n";
print $junk->{"_rfc822_message"}->head->header, "\n";
