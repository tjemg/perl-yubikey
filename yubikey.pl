use strict;
use warnings;
use Digest::HMAC_SHA1 qw(hmac_sha1 hmac_sha1_hex);

# 440000010203 24534206
# 440000010203 02855661
# 440000010203 03494637
# 440000010203 90092167

sub printHex ($) {
    my ($in) = @_;
    
    printf("0x%0.2x ", $_) for unpack "W*" => $in;
    print "\n";
}

sub computeOTP ($$) {
    ########################################################################################
    #  Input : Description                                                                 #
    ########################################################################################
    #  $key  : 160-bit key (as HEX string), eg. "90b6e1b47364fbe92b502d67fbaa33c947d9738e" #
    #  $cnt  : 64-bit counter, e.g. 0x0000000000000001                                     #
    ########################################################################################
    my ($key, $cnt) = @_;
    
    my $counter = pack "Q>"   => $cnt;
    my $k       = pack "H40"  => $key;
    my $HS      = hmac_sha1 $counter, $k;
    my @HS      = unpack "C*" => $HS;
    my $offset  = $HS[19] & 0x0f;
    my @code    = ( $HS[$offset+0] & 0x7f, $HS[$offset+1], $HS[$offset+2], $HS[$offset+3] );
    my $code    = hex(unpack "H*", pack "C*", @code);
    my @digits  = split //,$code;
    my @V       = @digits[ $#digits-8+1 .. $#digits ];
    my $V       = join "", @V;

    return $V;
}

my $key = "90b6e1b47364fbe92b502d67fbaa33c947d9738e";
for my $c (0..200) {
    my $OTP = computeOTP $key, $c;
    printf "%-5s : %s\n", $c, $OTP;
}

