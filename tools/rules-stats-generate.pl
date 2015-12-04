#!/usr/bin/perl

##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

use strict;
use warnings;

my $cmd_rules_debug = "./rules-debug.bin";

if (scalar @ARGV != 3)
{
  printf STDERR "usage: %s rules_file word_file out_file\n", $0;

  exit (-1);
}

my $rules_file = shift @ARGV;
my $word_file  = shift @ARGV;
my $out_file   = shift @ARGV;

my $rules;

open (RULES_FILE, "<", $rules_file) or die ("$rules_file: $!\n");

while (my $line = <RULES_FILE>)
{
  chomp ($line);

  next unless length $line;

  push (@{$rules}, $line);
}

close (RULES_FILE);

my $found;

open (OUT_FILE, "<", $out_file) or die ("$out_file: $!\n");

while (my $line = <OUT_FILE>)
{
  chomp ($line);

  next unless length $line;

  my $word = substr ($line, index ($line, ":") + 1);

  $found->{$word} = undef;
}

close (OUT_FILE);

for my $rule (@{$rules})
{
  my $tmp_rule   = "rules-debug.rule";
  my $tmp_result = "rules-debug.result";

  open (RULE, ">", $tmp_rule) or die ("$tmp_rule: $!\n");
  print RULE $rule, "\n";
  close (RULE);

  system ("$cmd_rules_debug $tmp_rule < $word_file > $tmp_result");

  open (RESULT, "<", $tmp_result) or die ("$tmp_result: $!\n");

  while (my $line = <RESULT>)
  {
    chomp ($line);

    next unless length $line;

    next unless exists $found->{$line};

    print $rule, "\n";

  }

  close (RESULT);
}


