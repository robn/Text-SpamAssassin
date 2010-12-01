package Text::SpamAssassin;

use 5.006;
use strict;
use warnings;

# internal modules (part of core perl distribution)
use POSIX qw(strftime);

# external modules (CPAN, etc.)
use Mail::SpamAssassin;

use Mail::Address;
use Mail::Header;
use Mail::Internet;

if ($Mail::SpamAssassin::VERSION < 3) {
    require Mail::SpamAssassin::NoMailAudit;

    # } else {
    #    require Mail::SpamAssassin::Message;
}

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Text::SpamAssassin ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = (
    'all' => [
        qw(

          )
    ]
);

our @EXPORT_OK = (@{$EXPORT_TAGS{'all'}});

our @EXPORT = qw(

);

# our $VERSION = '0.01';
(our $VERSION) = '$Revision: 1.2 $' =~ m#\$Revision:\s+(\S+)#o;

# Preloaded methods go here.

# Constructor
sub new {
    my $class = shift;
    my %opts  = @_;

    my $self = {
        'text'               => [],
        'response'           => {},
        'metadata'           => {},
        'spamassassin_prefs' => {},
        'header'             => {},
    };

    #		'option' => {},

    bless $self, $class;

    # initialize metadata, response, headers, email
    $self->_init;

    #	$self->{'option'} = {};

#	$self->{'option'}{'sa_prefs'} = {};
#	$self->{'option'}{'sa_prefs'}{'rules_filename'} = '/etc/spamassassin.rules';
#	$self->{'option'}{'sa_prefs'}{'userprefs_filename'} = './comment_spam_prefs.cf';

    # process %opts and fill in option, text, and metadata structs

    # Force data to be arrayref
    my $data = $opts{data};

    if (ref $data eq 'ARRAY') {
        $self->{'text'} = $data;
    } elsif (ref $data eq 'GLOB') {
        if (defined fileno $data) {
            $self->{'text'} = [<$data>];
        }
    } elsif (ref $data eq 'SCALAR') {
        $self->{'text'} = [${$data}];
    } else {
        $self->{'text'} = [$data];
    }

  argloop:
    foreach my $kk (keys %opts) {
        next argloop if ($kk eq 'text');
        next argloop if ($kk eq 'data');

        #		if ($kk eq 'option') {
        #			if (ref $opts{$kk} eq 'HASH') {
        #				foreach my $okk (keys %{$opts{$kk}}) {
        #				}
        #			}
        #			next argloop;
        #		}

        if ($kk eq 'spamassassin_prefs') {
            if (ref $opts{$kk} eq 'HASH') {
                foreach my $okk (keys %{$opts{$kk}}) {
                    $self->set_spamassassin_prefs($okk, $opts{$kk}{$okk});
                }
            }
            next argloop;
        }

        # treat all stray keys (not text, data, or option) as metadata
        $self->{'metadata'}{$kk} = $opts{$kk};
    }

    # Make a M::SA object; point to custom configs
    $self->{'_analyzer'} = Mail::SpamAssassin->new($self->{'sa_prefs'});

    return $self;
}

sub analyze {
    my $self = shift;

    # wipe response
    $self->_init_response;

    $self->_create_rfc822_message;

    # Get verdict, score, list of rules
    my $status = $self->{'_analyzer'}->check($self->{'_mail'});

    $self->{'response'}{'note'} ||= 'ANALYSIS REALLY FAILED';

    if ($status) {
        $self->{'response'}{'verdict'} =
          ($status->is_spam()) ? "SUSPICIOUS" : "OK";
        $self->{'response'}{'note'} = 'ANALYZED';  # add version number, timing?
        $self->{'response'}{'score'} = $status->get_hits();
        $self->{'response'}{'rules'} = $status->get_names_of_tests_hit();
        $status->finish();
    }

    # Handle missing return values...
    $self->{'response'}{'verdict'} ||= 'OK';
    $self->{'response'}{'note'}    ||= 'ANALYSIS REALLY FAILED';
    $self->{'response'}{'score'}   ||= 0;
    $self->{'response'}{'rules'}   ||= '';

    return $self->{'response'};
}

sub get_text {
    my $self = shift;
    return join('', @{$self->{'text'}});
}

sub set_text {
    my $self = shift;
    my $data = shift;

    if (ref $data eq 'ARRAY') {
        $self->{'text'} = $data;
    } elsif (ref $data eq 'GLOB') {
        if (defined fileno $data) {
            $self->{'text'} = [<$data>];
        }
    } elsif (ref $data eq 'SCALAR') {
        $self->{'text'} = [${$data}];
    } else {
        $self->{'text'} = [$data];
    }

    return;
}

sub get_spamassassin_prefs {
    my $self = shift;
    my $kk   = shift;

    return $self->_get_internals('spamassassin_prefs', $kk);
}

sub set_spamassassin_prefs {
    my $self = shift;
    my $kk   = shift;
    my $vv   = shift;

    return $self->_set_internals('spamassassin_prefs', $kk, $vv);
}

sub get_metadata {
    my $self = shift;
    my $kk   = shift;

    return $self->_get_internals('metadata', $kk);
}

sub set_metadata {
    my $self = shift;
    my $kk   = shift;
    my $vv   = shift;

    return $self->_set_internals('metadata', $kk, $vv);
}

sub get_response {
    my $self = shift;
    my $kk   = shift;

    return $self->_get_internals('response', $kk);
}

sub _get_internals {
    my $self = shift;
    my $ikk  = shift;
    my $kk   = shift;

    my $retval;

    if ($kk) {
        $retval = $self->{$ikk}{$kk}
          if (exists($self->{$ikk}{$kk}));
    } else {
        $retval = $self->{$ikk};
    }

    return $retval;
}

sub _set_internals {
    my $self = shift;
    my $ikk  = shift;
    my $kk   = shift;
    my $vv   = shift;

    $self->{$ikk}{$kk} = $vv;

    return;
}

sub _init {
    my $self = shift;

    # initialize metadata
    $self->_init_metadata;

    # initialize response
    $self->_init_response;

    # initialize mail
    $self->_init_mail;

    # initialize mail header info
    $self->_init_header;

    return;
}

sub _init_mail {
    my $self = shift;

    # initialize mail
    $self->{'mail'} = undef;

    return;
}

sub _init_sa_prefs {
    my $self = shift;

    # initialize mail
    $self->{'spamassassin_prefs'} = {};

    return;
}

sub _init_header {
    my $self = shift;

    # preload header defaults
    # These go into building Message-Id, Received, To, and From
    $self->{'header'}{'sender_ip'}      = '127.0.0.1';
    $self->{'header'}{'sender_name'}    = 'Anonymous Coward';
    $self->{'header'}{'sender_address'} = 'nobody@example.com';
    $self->{'header'}{'sender_host'}    = 'blog.example.com';

    $self->{'header'}{'recipient_host'}        = 'localhost';
    $self->{'header'}{'recipient_mta_version'} = '(Postfix)';
    $self->{'header'}{'recipient_address'}     = 'blog@example.com';

    $self->{'header'}{'Subject'}      = 'Eponymous';
    $self->{'header'}{'MIME-Version'} = '1.0';
    $self->{'header'}{'Content-Type'} = 'text/html; charset="us-ascii"';
    $self->{'header'}{'Content-Transfer-Encoding'} = '8bit';

    return;
}

sub _init_metadata {
    my $self = shift;

    # preload metadata
    $self->{'metadata'}{'author'}  = 'Anonymous Coward';
    $self->{'metadata'}{'email'}   = 'sender@example.com';
    $self->{'metadata'}{'ip'}      = '127.0.0.1';
    $self->{'metadata'}{'subject'} = 'Eponymous';
    $self->{'metadata'}{'url'}     = undef;

    return;
}

sub _init_response {
    my $self = shift;

    # preload response
    $self->{'response'}{'verdict'} = 'OK';
    $self->{'response'}{'note'}    = 'NOT ANALYZED';
    $self->{'response'}{'rules'}   = '';
    $self->{'response'}{'score'}   = 0;

    return;
}

sub _rndhex {
    my $self   = shift;
    my $length = shift || 0;
    my $retval = '';
    while ($length-- > 0) {
        $retval .= sprintf('%X', int(rand(16)));
    }
    return $retval;
}

sub _generate_mail_headers {
    my $self        = shift;
    my $Rl_hdrorder = shift;
    my $Rh_header   = shift;

    my @hdrorder = qw(
      Received
      Message-ID
      From
      To
      Subject
      Date
      MIME-Version
      Content-Type
      Content-Transfer-Encoding
    );
    push @{$Rl_hdrorder}, @hdrorder;

    $Rh_header->{'To'} ||= $self->{'header'}{'recipient_address'}
      || 'blog@example.com';

    $Rh_header->{'Date'} = strftime("%a, %d %b %Y %H:%M:%S %z", localtime);

    $Rh_header->{'From'} = Mail::Address->new(
             $self->{'metadata'}{'author'}
          || $self->{'header'}{'sender_name'}
          || 'Anonymous Coward',

        $self->{'metadata'}{'email'}
          || $self->{'header'}{'sender_address'}
          || 'nobody@example.com',
    )->format;

 #    if (exists($self->{'metadata'}{'subject'})
 #        && defined($self->{'metadata'}{'subject'})) {
 #        $Rh_header->{'Subject'} = $self->{'metadata'}{'subject'};
 #    } else {
 #        $Rh_header->{'Subject'} = $self->{'header'}{'Subject'} || 'Eponymous';
 #    }

    $Rh_header->{'Subject'} = $self->{'metadata'}{'subject'}
      || $self->{'header'}{'Subject'}
      || 'Eponymous';

    if (exists($self->{'metadata'}{'url'})
        && defined($self->{'metadata'}{'url'})) {
        my $fake_title =
            'Title: <a href="'
          . $self->{'metadata'}{'url'} . '">'
          . $Rh_header->{'Subject'}
          . "</a>\n";
    }

    $self->{'metadata'}{'ip'} = $self->{'header'}{'sender_ip'}
      unless (exists($self->{'metadata'}{'ip'})
        && defined($self->{'metadata'}{'ip'}));

    $Rh_header->{'Received'} = 'from '
      . $self->{'metadata'}{'ip'} . ' (['
      . $self->{'metadata'}{'ip'}
      . ']) by '
      . ($self->{'header'}{'recipient_host'}        || 'localhost') . ' '
      . ($self->{'header'}{'recipient_mta_version'} || '(Postfix)')
      . ' with SMTP id '
      . $self->_rndhex(10)
      . ' for <'
      . $Rh_header->{'To'} . '>; '
      . $Rh_header->{'Date'};

    $Rh_header->{'Message-ID'} = '<'
      . $self->_rndhex(12) . '$'
      . $self->_rndhex(8) . '$'
      . $self->_rndhex(8) . '@'
      . ($self->{'header'}{'sender_host'} || 'blog.example.com') . '>';

    $Rh_header->{'MIME-Version'}              = '1.0';
    $Rh_header->{'Content-Type'}              = 'text/html; charset="us-ascii"';
    $Rh_header->{'Content-Transfer-Encoding'} = '8bit';

    my $Rl_tmphdr = [];
    foreach my $hdr (@hdrorder) {
        if (exists($Rh_header->{$hdr}) && defined($Rh_header->{$hdr})) {
            push @{$Rl_tmphdr}, $hdr . ': ' . $Rh_header->{$hdr};
        }
    }

    return Mail::Header->new($Rl_tmphdr);

    #	return;

}

sub _create_rfc822_message {
    my $self = shift;

    # Fake up some email headers
    my @hdrorder = ();
    my %header   = ();

    #	$self->_generate_mail_headers(\@hdrorder, \%header, );
    my $Rl_header = $self->_generate_mail_headers(\@hdrorder, \%header,);

    my $Rl_body = [
        '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">' . "\n",
        '<HTML><HEAD><TITLE>Analyzed Comment</TITLE></HEAD><BODY>' . "\n",
        @{$self->{'text'}},
        '</BODY></HTML>' . "\n",
    ];

    $self->{'_rfc822_message'} =
      Mail::Internet->new('Header' => $Rl_header, 'Body' => $Rl_body);

    # Fake up a mail message and stuff the text in the body
    if ($Mail::SpamAssassin::VERSION < 3) {

        # This is totally stupid. M::SA::NMA goes all stupid if [data] isn't
        # broken into lines.
        $self->{'_mail'} =
          Mail::SpamAssassin::NoMailAudit->new(
            'data' => [split(/\n/, $self->{'_rfc822_message'}->as_string)]);
    } else {
        $self->{'_mail'} =
          Mail::SpamAssassin::Message->new(
            {'message' => $self->{'_rfc822_message'}->as_string});
    }

    return;
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
