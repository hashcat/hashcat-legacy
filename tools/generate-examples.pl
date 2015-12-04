#!/usr/bin/perl

##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

use strict;
use warnings;
use Digest::MD5 qw (md5_hex);
use Digest::SHA1 qw (sha1_hex);
use MIME::Base64;

my $tmp_hash = "hash";
my $tmp_word = "word";
my $tmp_out  = "out";

#my $hashcat = "./hashcat-cli.bin";
my $hashcat = "hashcat-cli.exe";

my $runs_per_test = 1;

my $num_words_min = 100;
my $num_words_max = 104;

my $word_len_min  = 1;
my $word_len_max  = 55;

my $word_chr_min  = 0x20;
my $word_chr_max  = 0x7e;

my $salt_len_min  = 1;
my $salt_len_max  = 54;

test14 ();

exit;

sub simple_generate
{
  for (1..$runs_per_test)
  {
    my $num_words = get_random_num ($num_words_min, $num_words_max);

    my %dupe;

    my $left = 10;

    while ($left)
    {
      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, 16);

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

      print $word_buf, "\n";

      $left--;
    }
  }
}

sub test24
{
  my $test_num = 24;

  my $tmp_word = "examples/A0.M300.word";
  my $tmp_hash = "examples/A0.M300.hash";

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

      my $ctx = Digest::SHA1->new;

      $ctx->add ($word_buf);

      my $hash_buf = sha1_hex ($ctx->digest);

      print OUTH $hash_buf, "\n";

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);
  }
}

sub test23
{
  my $test_num = 23;

  my $tmp_word = "examples/A0.M700.word";
  my $tmp_hash = "examples/A0.M700.hash";

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

      my $ctx = Digest::SHA1->new;

      $ctx->add ($word_buf);
      $ctx->add ($salt_buf);

      my $hash_buf = "{SSHA}" . encode_base64 ($ctx->digest . $salt_buf);

      print OUTH $hash_buf;

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);
  }
}

sub test22
{
  my $test_num = 22;

  my $tmp_word = "examples/A0.M600.word";
  my $tmp_hash = "examples/A0.M600.hash";

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

      my $ctx = Digest::SHA1->new;

      $ctx->add ($word_buf);

      my $hash_buf = "{SHA}" . encode_base64 ($ctx->digest);

      print OUTH $hash_buf;

      $left--;
    }

    close (OUTH);
    close (OUTP);

    unlink ($tmp_out);
  }
}

sub test21
{
  my $test_num = 21;

  my $tmp_word = "examples/A0.M5.VBULLSALT.word";
  my $tmp_hash = "examples/A0.M5.VBULLSALT.hash";

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

      my $salt_len = get_random_num (3, 3);

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr (0x20, 0x7e));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = get_random_num ($word_len_min, 30);

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
  }
}

sub test20
{
  my $test_num = 20;

  my $tmp_word = "examples/A0.M104.word";
  my $tmp_hash = "examples/A0.M104.hash";

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

  }
}

sub test19
{
  my $test_num = 19;

  my $tmp_word = "examples/A0.M103.word";
  my $tmp_hash = "examples/A0.M103.hash";

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
  }
}

sub test18
{
  my $test_num = 18;

  my $tmp_word = "examples/A3.M0.word";
  my $tmp_hash = "examples/A3.M0.hash";

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
  }
}

sub test16
{
  my $test_num = 16;

  my $tmp_word = "examples/A0.M11.word";
  my $tmp_hash = "examples/A0.M11.hash";

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

      my $salt_len = get_random_num (1, 10);

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
  }
}

sub test17
{
  my $test_num = 17;

  my $tmp_word = "examples/A0.M12.word";
  my $tmp_hash = "examples/A0.M12.hash";

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
  }
}

sub test13
{
  my $test_num = 13;

  my $tmp_word = "examples/A0.M100.word";
  my $tmp_hash = "examples/A0.M100.hash";

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

  }
}

sub test14
{
  my $test_num = 14;

  my $tmp_word = "examples/A0.M101.word";
  my $tmp_hash = "examples/A0.M101.hash";

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
  }
}

sub test15
{
  my $test_num = 15;

  my $tmp_word = "examples/A0.M102.word";
  my $tmp_hash = "examples/A0.M102.hash";

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
  }
}

##
## test1 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 0.
##

sub test1
{
  my $test_num = 1;

  my $tmp_word = "examples/A0.M0.word";
  my $tmp_hash = "examples/A0.M0.hash";

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
  }
}

##
## test2 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 1.
##

sub test2
{
  my $test_num = 2;

  my $tmp_word = "examples/A0.M1.word";
  my $tmp_hash = "examples/A0.M1.hash";

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
  }
}

##
## test3 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 2.
##

sub test3
{
  my $test_num = 3;

  my $tmp_word = "examples/A0.M2.word";
  my $tmp_hash = "examples/A0.M2.hash";

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
  }
}

##
## test4 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 3.
##

sub test4
{
  my $test_num = 4;

  my $tmp_word = "examples/A0.M3.word";
  my $tmp_hash = "examples/A0.M3.hash";

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
  }
}

##
## test5 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 4.
##

sub test5
{
  my $test_num = 5;

  my $tmp_word = "examples/A0.M4.word";
  my $tmp_hash = "examples/A0.M4.hash";

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
  }
}

##
## test6 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 5.
##

sub test6
{
  my $test_num = 6;

  my $tmp_word = "examples/A0.M5.word";
  my $tmp_hash = "examples/A0.M5.hash";

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

      my $salt_len = get_random_num (1, 10);

      my @salt_arr;

      for (my $i = 0; $i < $salt_len; $i++)
      {
        push (@salt_arr, get_random_chr ($word_chr_min, $word_chr_max));
      }

      my $salt_buf = join ("", @salt_arr);

      ##
      ## word
      ##

      my $word_len = get_random_num (1, 40);

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
  }
}

##
## test7 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 6.
##

sub test7
{
  my $test_num = 7;

  my $tmp_word = "examples/A0.M6.word";
  my $tmp_hash = "examples/A0.M6.hash";

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
  }
}

##
## test8 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 1.
##

sub test8
{
  my $test_num = 8;

  my $tmp_word = "examples/A1.M0.word";
  my $tmp_hash = "examples/A1.M0.hash";

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
  }
}

##
## test9 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 7.
##

sub test9
{
  my $test_num = 9;

  my $tmp_word = "examples/A0.M7.word";
  my $tmp_hash = "examples/A0.M7.hash";

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
  }
}

##
## test10 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 8.
##

sub test10
{
  my $test_num = 10;

  my $tmp_word = "examples/A0.M8.word";
  my $tmp_hash = "examples/A0.M8.hash";

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
  }
}

##
## test11 : random number of passwords, random word length, random chars, 10 times
##       : simple out -a 0 -m 9.
##

sub test11
{
  my $test_num = 11;

  my $tmp_word = "examples/A0.M9.word";
  my $tmp_hash = "examples/A0.M9.hash";

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
  }
}

sub test12
{
  my $test_num = 12;

  my $tmp_word = "examples/A0.M10.word";
  my $tmp_hash = "examples/A0.M10.hash";

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
