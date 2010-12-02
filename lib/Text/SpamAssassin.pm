package Text::SpamAssassin;

use 5.006;
use strict;
use warnings;

use Mail::SpamAssassin;
use Mail::Address;
use Mail::Header;
use Mail::Internet;
use POSIX qw(strftime);
use Data::Random qw(rand_chars);

BEGIN {
    if ($Mail::SpamAssassin::VERSION < 3) {
        require Mail::SpamAssassin::NoMailAudit;
    }
}

sub new {
    my ($class, %opts) = @_;

    my $self = bless {}, $class;
    $self->reset;

    $self->{analyzer} = Mail::SpamAssassin->new(%opts);
    $self->{analyzer}->compile_now;

    return $self;
}

sub reset {
    my ($self) = @_;

    $self->reset_metadata;
    $self->reset_headers;

    return $self;
}

sub reset_metadata {
    my ($self) = @_;

    $self->{metadata} = {};

    return $self;
}

sub reset_headers {
    my ($self) = @_;

    $self->{header} = {};

    return $self;
}

sub set_metadata {
    my ($self, $key, $value) = @_;

    if (defined $value) {
        $self->{metadata}{lc $key} = $value;
    }
    else {
        delete $self->{metadata}{lc $key};
    }

    return $self;
}

sub set_header {
    my ($self, $key, $value) = @_;

    $value = [ $value ] if not ref $value;

    if (defined $value) {
        $self->{header}{lc $key} = $value;
    }
    else {
        delete $self->{header}{lc $key};
    }

    return $self;
}

sub set_text {
    my ($self, $text) = @_;

    $self->{text} = $text;
    delete $self->{html};

    return $self;
}

sub set_html {
    my ($self, $html) = @_;

    $self->{html} = $html;
    delete $self->{text};

    return $self;
}

sub analyze {
    my ($self) = @_;

    my $msg = $self->_generate_message;

    my $status = $self->{analyzer}->check($msg);
    if (! $status) {
        return {
            verdict => 'UNKNOWN',
            score   => 0,
            rules   => '',
        };
    }

    my $result = {
        verdict => $status->is_spam ? 'SUSPICIOUS' : 'OK',
        score   => $status->get_hits,
        rules   => $status->get_names_of_tests_hit,
    };

    $status->finish;

    return $result;
}

sub _generate_header {
    my ($self) = @_;

    my $h = Mail::Header->new;

    for my $key ( keys %{$self->{headers}} ) {
        $h->add($key, $_) for @{$self->{headers}{$key}};
    }

    my $set = sub {
        my ($key, $value) = @_;
        $h->get($key) or $h->add($key, $value);
    };

    $set->('To' => q{blog@example.com});
    $set->('From' => Mail::Address->new(
        $self->{metadata}{author} || q{Anonymous Coward},
        $self->{metadata}{email}  || q{nobody@example.com},
    )->format);
    $set->('Subject' => $self->{metadata}{subject} || q{Eponymous});

    $set->('Date' => strftime("%a, %d %b %Y %H:%M:%S %z", localtime));

    $set->('Received' => sprintf (
        q{from %s ([%s]) by localhost (Postfix) with SMTP id %s for <blog@example.com>; %s},
        $self->{metadata}{ip} || q{127.0.0.1},
        $self->{metadata}{ip} || q{127.0.0.1},
        (join '', rand_chars(set => 'alphanumeric', size => 10)),
        strftime("%a, %d %b %Y %H:%M:%S %z", localtime),
    ));

    $set->('Message-Id', sprintf (
        q{<%s@%s.example.com>},
        (join '', rand_chars(set => 'alphanumeric', size => 32)),
        (join '', rand_chars(set => 'alphanumeric', size => 10)),
    ));

    $set->('MIME-Version', q{1.0});
    $set->('Content-Transfer-Encoding', q{8bit});

    if ( $self->{html} ) {
        $set->('Content-Type', q{text/html; charset="us-ascii"});
    }
    else {
        $set->('Content-Type', q{text/plain; charset="us-ascii"});
    }

    return $h;
}

sub _generate_body {
    my ($self) = @_;

    my @lines;

    if ( $self->{text} ) {
        @lines = (
            (map { "$_: $self->{metadata}{$_}" } sort keys %{$self->{metadata}}),
            (keys %{$self->{metadata}} ? q{} : ()),
            $self->{text},
        );
    }

    elsif ( $self->{html} ) {
        @lines = (
            q{<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">},
            q{<html><head><title>Anazlyzed comment</title></head><body>},
            $self->{html},
            q{</body></html>},
        );
    }

    return join "\n", @lines;
}

sub _generate_message {
    my ($self) = @_;

    my $msg = Mail::Internet->new(
        Header => $self->_generate_header,
        Body   => [$self->_generate_body],
    );

    if ($Mail::SpamAssassin::VERSION < 3) {
        return Mail::SpamAssassin::NoMailAudit->new(
            data => [ split(/\n/, $msg->as_string) ],
        );
    }

    return Mail::SpamAssassin::Message->new({
        message => $msg->as_string,
    });
}

1;
__END__

=head1 NAME

Text::SpamAssassin - Detects spamminess of arbitrary text, suitable for wiki and blog defense.

=head1 SYNOPSIS

  use Text::SpamAssassin;
  my %sa_prefs = {
    'userprefs_filename' => '/etc/spamassassin/comment_spam_prefs.cf',
    'rules_filename' => '/etc/spamassassin.rules',
  };
  my $tester = Text::SpamAssassin->new(
    'data'   => \@comment,
    'spamassassin_prefs' => \%sa_prefs,
    'header' => {
      'recipient_address' => 'manos@example.com',
      'Content-Type'      => 'text/plain; charset="us-ascii"',
    },
    'title' => $post_title,
    'ip' => $originating_ip,
    'author' => $author_name,
    'email' => $author_email,
    'url' => $author_url,
    'pizzaguy' => 'torgo',
  );
  my $Rh_results = $tester->analyze;
  print "Verdict: " . $Rh_results->{'verdict'} . "\n";

  my $fester = Text::SpamAssassin->new();
  $tester->set_text(@content);
  $tester->set_metadata('ip', $originating_ip);
  $tester->set_metadata('email', $author_email);
  $tester->set_metadata('url', $author_url);
  $tester->set_spamassassin_prefs('userprefs_filename', '/etc/spamassassin/comment_spam_prefs.cf');
  $tester->analyze;
  $verdict = $tester->get_response('verdict');

=head1 ABSTRACT

Text::SpamAssassin accepts text and metadata (comment title, poster's name, email address, url, and IP address), and produces a RFC822-formatted mail message for analysis with Mail::SpamAssassin. Additionally, new rulesets and user preferences can be passed to Mail::SpamAssassin to adjust the rules and scores applied to the mail message, since certain tests bear no relevance to comment spam (e.g. DUL network tests)

Results include verdict (OK or SUSPICIOUS), note (shows whether tests completed successfully), score, and rules (the list of rules hit.)

=head1 DESCRIPTION

I should describe the constructor here, how it takes a hash of arguments, including:

    # the actual text to be analyzed, as a reference to a list of lines
    'data'   => \@comment,

    # a hash of SpamAssassin preferences (see Mail::SpamAssassin::Conf)
    'spamassassin_prefs' => \%sa_prefs,

    # a hash of RFC822 mail header elements
    'header' => \%header,

where the defaults are:

 %header = (
   'sender_ip'                 => '127.0.0.1',
   'sender_name'               => 'Anonymous Coward',
   'sender_address'            => 'nobody@example.com',
   'sender_host'               => 'blog.example.com',
   
   'recipient_host'            => 'localhost',
   'recipient_mta_version'     => '(Postfix)',
   'recipient_address'         => 'blog@example.com',
   
   'Subject'                   => 'Eponymous',
   'MIME-Version'              => '1.0',
   'Content-Type'              => 'text/html; charset="us-ascii"',
   'Content-Transfer-Encoding' => '8bit',
 )

The remainder of the elements are treated as metadata. The only metadata that are really relevant are 'email', 'subject', 'ip', 'url', and 'author'. The remainder will be added to the message body, but only those five fields are used when constructing the faux email headers.

Note that metadata trumps %header when constructing the mail headers with some hardcoded defaults lingering if you manage to totally mangle anything. Consider this to be enough rope with which to hang yourself.

There are get and set accessors for text, spamassassin_prefs, and metadata (set_text([ 'mumble content mumble']), set_spamassassin_prefs('userprefs_filename', '/home/blog/sa.cf'), and set_metadata('ip', $ip); get_... accessors work as you might expect. get_response('field') works too, where 'field' is one of 'verdict', 'note', 'score', 'and rules'. 'rules' may be empty.

Basically, you build the Text::SpamAssassin object, load it with data, invoke the analyze() method (which returns a hash reference with the four keys as mentioned above), and use the returned hash reference or access methods to determine whether the text is spammy-looking. If the analyzer runs into trouble, it sets 'verdict' to 'OK', under the assumption that it's better to leak some spam through than delay (or delete) legitimate posts.

=head2 EXPORT

None by default.

=head1 BUGS

=over 4

=item * Test suite is virtually non-existant. Needs more torture.

=item * I'm not an OO programmer so there's bound to be metric buttloads of problems with my design (my UML books are used to shore up the short leg of the coffee table, and I use my copies of Riel's "Object-Oriented Design Heuristics" and The Gang of Four's "Design Patterns" to press flowers.) Seriously though, this was refactored from procedural code so it doubtless has a few warts and quirks.

=item * The documentation appears to have been written by a drunkard.

=item * "These rubber pants are hot." - Ralph Wiggum

=back

=head1 TO DO

=over 4

=item * Find and fix bugs.

=item * Clean up OO design.

=item * Look for ways to speed this up (contribute babycartd?)

=item * Give users better control over comment's mail headers. One could subclass the module and replace the offensive innards of _generate_mail_headers() and _create_rfc822_message() but one probably shouldn't have to. The current attempt at making header information accessible is messy.

=item * Give users more control over failure status, e.g. treat unanalyzed messages be marked SUSPICIOUS rather than OK. You can detect negative and 'administratively negative' now so this isn't a big issue.

=item * Build a decent comment_spam_prefs.cf file.

=item * Verify SpamAssassin 3.x compatibility.

=item * Add more gratuitous references to Zatoichi the Blind Swordsman and Ogami Itto from Lone Wolf & Cub. gara, gara, gara...

=back

=head1 SEE ALSO

Mail::SpamAssassin

http://www.surbl.org

http://www.austinimprov.com/~apthorpe/code/babycart

=head1 AUTHOR

Bob Apthorpe, E<lt>apthorpe+babycart@cynistar.netE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2004 by Bob Apthorpe

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
