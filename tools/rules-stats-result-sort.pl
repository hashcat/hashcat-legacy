#!/usr/bin/perl

##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

use strict;
use warnings;

my $min = shift @ARGV;

my $rules;

while (my $line = <>)
{
  chomp ($line);

  $rules->{$line}++;
}

for my $rule (sort { $rules->{$b} <=> $rules->{$a} } keys %{$rules})
{
  next if ($rules->{$rule} < $min);

  my @tmp = split //, $rule;

  next if ((scalar @tmp == 3) && (lc $tmp[1] eq lc $tmp[2]));

  print $rule, "\n";
}
