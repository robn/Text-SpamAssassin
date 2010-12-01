<?php
/*
* $Id: comment_tester.php,v 1.1 2004/09/03 01:00:19 apthorpe Exp apthorpe $
* Author: Bob Apthorpe <apthorpe+babycart@cynistar.net>
* Proof-of-concept PHP fragment to flag blog/wiki spam
*/


// $ip='66.143.181.11'

// $X_babycart = '/usr/bin/perl /home/apthorpe/pjx/babycart/babycart';
$X_babycart = './babycart';

// Get comment (add user and user's URL as well)
$comment = '';
$stdin = fopen('php://stdin', 'r');
while (!feof($stdin)) {
	$comment .= fgets($stdin);
//	$comment .= trim(fgets($stdin));
}
fclose($stdin);

print "Comment:\n$comment\n==========\n";

$descriptorspec = array(
	0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
	1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
	2 => array("file", "./error-output.txt", "a") // stderr is a file to write to
);

$process = proc_open($X_babycart, $descriptorspec, $pipes);
if (is_resource($process)) {
	// $pipes now looks like this:
	// 0 => writeable handle connected to child stdin
	// 1 => readable handle connected to child stdout
	// Any error output will be appended to /tmp/error-output.txt

	fwrite($pipes[0], $comment);
	fclose($pipes[0]);

	$response = '';
	while (!feof($pipes[1])) {
		$response .= fgets($pipes[1], 1024);
	}
	fclose($pipes[1]);

	print "Response: $response\n";
	// split into status, note, score, rules...

	// It is important that you close any pipes before calling
	// proc_close in order to avoid a deadlock
	$return_value = proc_close($process);

	echo "command returned $return_value\n";
}
?> 
