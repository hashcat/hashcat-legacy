#!/usr/bin/perl

##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

use strict;
use warnings;
use Digest::MD5 qw (md5_hex);
use Digest::SHA qw (sha1_hex);
use MIME::Base64;

my $tmp_hash = "hash";
my $tmp_word = "word";
my $tmp_out  = "out";

my $hashcat = "./hashcat-cli64.bin";
#my $hashcat = "hashcat-cli64.exe";

my $runs_per_test  = 3;

my $num_words_min = 1;
my $num_words_max = 1111;

my $word_len_min  = 1;
my $word_len_max  = 55;

my $word_chr_min  = 0x20;
my $word_chr_max  = 0xff;

my $salt_len_min   = 1;
my $salt_len_max   = 54;


print "test1\n";
test1 ();
print "test2\n";
test2 ();
print "test3\n";
test3 ();
print "test4\n";
test4 ();
print "test5\n";
test5 ();
print "test6\n";
test6 ();
print "test7\n";
test7 ();
print "test8\n";
test8 ();
print "test9\n";
test9 ();
print "test10\n";
test10 ();
print "test11\n";
test11 ();
#print "test12\n";
#test12 ();
print "test13\n";
test13 ();
#print "test14\n";
#test14 ();
#print "test15\n";
#test15 ();
print "test16\n";
test16 ();
print "test17\n";
test17 ();
#print "test18\n";
#test18 ();
print "test19\n";
test19 ();
print "test20\n";
test20 ();
print "test21\n";
test21 ();
print "test22\n";
test22 ();
print "test23\n";
test23 ();

sub test44
{
  for (1..1)
  {
    my $left = 5;

my %dupe;

    while ($left)
    {

      ##
      ## word
      ##

      my $word_len = 8;

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
       push (@word_arr, get_random_chr (0x61, 0x7a));
#        push (@word_arr, get_random_chr (0x41, 0x4a));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print md5_hex ($word_buf), "\n";

      $left--;
    }
  }
}

sub test23
{
  my $test_num = 23;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash) or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = 8;

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max - 8);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $ctx = Digest::SHA->new;

      $ctx->add ($word_buf);
      $ctx->add ($salt_buf);

      my $hash_buf = "{SSHA}" . encode_base64 ($ctx->digest . $salt_buf);

      print OUTH $hash_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "111", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}


sub test22
{
  my $test_num = 22;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $ctx = Digest::SHA->new;

      $ctx->add ($word_buf);

      my $hash_buf = "{SHA}" . encode_base64 ($ctx->digest);

      print OUTH $hash_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "101", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

sub test21
{
  my $test_num = 21;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = get_random_num (2, 2);

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr (0x30, 0x39));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max - $salt_len);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex (md5_hex ($word_buf) . $salt_buf);

      print OUTH $hash_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "2611", "-e", "salts/brute-oscommerce.salt", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

sub test20
{
  my $test_num = 20;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = sha1_hex (sha1_hex (sha1_hex ($word_buf)));

      print OUTH $hash_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "4600", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

sub test19
{
  my $test_num = 19;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = sha1_hex (sha1_hex ($word_buf));

      print OUTH $hash_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "4500", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

sub test18
{
  my $test_num = 18;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## word
      ##

      my $word_len = 5;

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr (0x61, 0x7a));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex ($word_buf);

      print OUTH $hash_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "3", "-m", "0", "-o", $tmp_out, $tmp_hash, "--pw-min=5", "--pw-max=5");

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

sub test16
{
  my $test_num = 16;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = 10;

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = 10;

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex ($salt_buf . md5_hex ($salt_buf . $word_buf));

      print OUTH $hash_buf, ":", $salt_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "4010", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

sub test17
{
  my $test_num = 17;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = 10;

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = 10;

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex ($salt_buf . md5_hex ($word_buf . $salt_buf));

      print OUTH $hash_buf, ":", $salt_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "4110", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

sub test13
{
  my $test_num = 13;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      my $word_len = get_random_num ($word_len_min, $word_len_max);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      print OUTP $word_buf, "\n";

      my $hash_buf = sha1_hex ($word_buf);

      print OUTH $hash_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "100", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

sub test14
{
  my $test_num = 14;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = get_random_num ($salt_len_min, $salt_len_max);

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max - $salt_len);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = sha1_hex ($word_buf . $salt_buf);

      print OUTH $hash_buf, ":", $salt_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "101", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

sub test15
{
  my $test_num = 15;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = get_random_num ($salt_len_min, $salt_len_max);

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max - $salt_len);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = sha1_hex ($salt_buf . $word_buf);

      print OUTH $hash_buf, ":", $salt_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "102", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}


##
## test1 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 0.
##

sub test1
{
  my $test_num = 1;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      my $word_len = get_random_num ($word_len_min, $word_len_max);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex ($word_buf);

      print OUTH $hash_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "0", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

##
## test2 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 10.
##

sub test2
{
  my $test_num = 2;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = get_random_num ($salt_len_min, $salt_len_max);

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max - $salt_len);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex ($word_buf . $salt_buf);

      print OUTH $hash_buf, ":", $salt_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "10", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

##
## test3 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 20.
##

sub test3
{
  my $test_num = 3;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = get_random_num ($salt_len_min, $salt_len_max);

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max - $salt_len);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex ($salt_buf . $word_buf);

      print OUTH $hash_buf, ":", $salt_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "20", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

##
## test4 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 2600.
##

sub test4
{
  my $test_num = 4;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex (md5_hex ($word_buf));

      print OUTH $hash_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "2600", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

##
## test5 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 3500.
##

sub test5
{
  my $test_num = 5;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex (md5_hex (md5_hex ($word_buf)));

      print OUTH $hash_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "3500", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

##
## test6 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 2611.
##

sub test6
{
  my $test_num = 6;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = get_random_num ($salt_len_min, $salt_len_max - 32);

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max - $salt_len);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex (md5_hex ($word_buf) . $salt_buf);

      print OUTH $hash_buf, ":", $salt_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "2611", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

##
## test7 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 3610.
##

sub test7
{
  my $test_num = 7;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = 32;

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max - 32);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex (md5_hex ($salt_buf) . $word_buf);

      print OUTH $hash_buf, ":", $salt_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "3610", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

##
## test7 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 1.
##

sub test8
{
  my $test_num = 8;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## word
      ##

      my $word_len = get_random_num (6, 14);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      my $word_buf_sep = int ($word_len / 2);

      my $word_buf_left  = substr ($word_buf, 0, $word_buf_sep);
      my $word_buf_right = substr ($word_buf, $word_buf_sep);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf_left,  "\n";
      print OUTP $word_buf_right, "\n";

      my $hash_buf = md5_hex ($word_buf);

      print OUTH $hash_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "1", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

##
## test9 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 3710.
##

sub test9
{
  my $test_num = 9;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = get_random_num ($salt_len_min, $salt_len_max - 32);

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max - $salt_len);

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex ($salt_buf . md5_hex ($word_buf));

      print OUTH $hash_buf, ":", $salt_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "3710", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

##
## test10 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 3810.
##

sub test10
{
  my $test_num = 10;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = 10;

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, $word_len_max - ($salt_len * 2));

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex ($salt_buf . $word_buf . $salt_buf);

      print OUTH $hash_buf, ":", $salt_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "3810", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

##
## test11 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 2811.
##

sub test11
{
  my $test_num = 11;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = 10;

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = 10;

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex (md5_hex ($salt_buf) . md5_hex ($word_buf));

      print OUTH $hash_buf, ":", $salt_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "2811", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}

sub test12
{
  my $test_num = 12;

  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    open (OUTP, ">", $tmp_word) or die ("$tmp_word: $!\n");
    open (OUTH, ">", $tmp_hash)  or die ("$tmp_hash: $!\n");

    my %dupe;

    my $left = $num_words;

    while ($left)
    {
      ##
      ## salt
      ##

      my $salt_len = 10;

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = 10;

      my @word_arr;

      for (my $i = 0; $i < $word_len; $i++)
      {
        push (@word_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $word_buf = join ("", @word_arr);

      ##
      ## dupe
      ##

      next if exists $dupe{$word_buf};

      $dupe{$word_buf} = undef;

      ##
      ## store
      ##

      print OUTP $word_buf, "\n";

      my $hash_buf = md5_hex (md5_hex ($word_buf) . md5_hex ($salt_buf));

      print OUTH $hash_buf, ":", $salt_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);

    my $rc = system ($hashcat, "-a", "0", "-m", "10", "-o", $tmp_out, $tmp_hash, $tmp_word);

    comword ($test_num, "rc") if ($rc != 0);

    my $lines = get_lines_in_file ($tmp_out);

    comword ($test_num, "numlines") if ($lines != $num_words);
  }
}


##
## subs
##

sub comword
{
  my $test_num = shift;

  my $msg = shift;

  die ("$test_num: $msg\n");
}

sub get_lines_in_file
{
  my $file = shift;

  my $count = 0;

  open (IN, $file) or die ("$file: $!\n");

  while (<IN>) { $count++ }

  close (IN);

  return $count;
}

sub get_random_num
{
  my $min = shift;
  my $max = shift;

  return int ((rand ($max - $min)) + $min);
}

sub get_random_chr
{
  return chr get_random_num (@_);
}
