#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use MIME::Base64 qw (encode_base64 decode_base64);

use Crypt::CBC;
use Digest::HMAC qw (hmac hmac_hex);
use Digest::SHA  qw (sha256);

sub module_constraints { [[0, 256], [1, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $mac = shift // random_hex_string(32);
  my $iv = shift // random_hex_string(16);
  my $iter = shift // 100000;
  
  my $master_key = shift;


  # derive key from pin
  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter,
    output_len => 32
  );

  my $tmp = $pbkdf2->PBKDF2 ($salt, $word);
  
  if(defined($master_key) == 0)
  {
    $master_key = random_hex_string(32);
    # expand for encryption
    my $expanded_enc = hmac (sprintf("enc%c", 0x01), $tmp, \&sha256);

    my $aes = Crypt::CBC->new (-cipher => 'Cipher::AES',
                               -pbkdf => 'none',
                               -pass    => $expanded_enc,
                               -keysize => 32,
                               -iv => $iv);

    $master_key = $aes->encrypt($master_key, $expanded_enc, $iv);
  }

  my $expanded_mac = hmac (sprintf("mac%c", 0x01), $tmp, \&sha256);
  
  my $hash_hmac = hmac ($iv . $master_key, $expanded_mac, \&sha256);

  my $hash = sprintf ("\$bitwardenpin\$1*%d*%s*%s*%s*%s", $iter, encode_base64 ($salt, ""), encode_base64 ($iv, ""), encode_base64($master_key, ""), encode_base64 ($hash_hmac, ""));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined ($hash);
  return unless defined ($word);

  return unless substr ($hash, 0, 15) eq '$bitwardenpin$1';

  my ($type, $iter, $salt_base64, $iv_base64, $enc_key_base64, $mac_base64) = split ('\*', $hash);

  return unless defined ($type);
  return unless defined ($iter);
  return unless defined ($salt_base64);
  return unless defined ($iv_base64);
  return unless defined ($enc_key_base64);
  return unless defined ($mac_base64);

  $type = substr ($type, 14);

  return unless ($type eq '1');
  return unless ($iter =~ m/^[0-9]{1,7}$/);
  return unless ($salt_base64 =~ m/^[a-zA-Z0-9+\/=]+$/);
  return unless ($enc_key_base64 =~ m/^[a-zA-Z0-9+\/=]+$/);
  return unless ($mac_base64 =~ m/^[a-zA-Z0-9+\/=]+$/);

  my $salt = decode_base64 ($salt_base64);

  my $iv = decode_base64 ($iv_base64);

  my $master_key = decode_base64 ($enc_key_base64);
  
  my $mac = decode_base64($mac_base64);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $mac, $iv, $iter, $master_key);

  return ($new_hash, $word);
}

1;
