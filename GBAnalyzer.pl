use Data::Dumper;
$path1='UKPKRPSDCGB06.txt';


my %obj_list=();
my %obj_anc=();
my %pt_rulemap=();
my %out_rulemap=();
my %rev_pair=();
my %dup_pair=();
my @res=();

&rulebase();

sub rulebase
{
	#my @arr=&ret_arr("Pass Through","  Hosts/Networks");
	my @arr1=&ret_arr("  Outbound","  Remote Access");
	my @arr=&ret_arr("IP Pass Through","  Hosts/Networks");
	#print $#arr;
	&obj_map();
	&parse_rules('passthrough',\@arr);
	&parse_rules('outbound',\@arr1);
	&create_ancestor();
	#&remoteaccess();
}

#&get_rules('<SEMA_CON>','passthrough');

#&printobj();

sub obj_map
{
my @out=&ret_arr("Objects","VPN Objects");
#print $#out;
my $str="";
	foreach my$l(@out)
	{
	$str=$str.$l;
	}
#print $str;
my @par1=split(/\n\n/,$str);
#print $#par1;
my $in=1;
#print Dumper(\@par1);
foreach $l(@par1)
{
	#print "$in\n";
	my @a=split(/\n/,$l);	
	my @all_vals=();
	my $oname;
	my @vals=();
	#@a=&treat(@a);
	foreach $m(@a)
	{
		$l1=$m;
		if($m=~/\s*\d/)
		{
			if($l1=~/^\s{4}\d/)
			{
				#print $1."\n";
				#$oname=$1;
				my @a2=split(/-\s/,$l1);
				#print "$a2[0]\n";
				my @a3=split(/\s{2,}/,$a2[0]);
				$oname=$a3[$#a3];
				$oname=~s/\s*$//;
			}			
			if($l1=~/\s{14}\d{1,3}\s*(o*\s*<*(\w|-|\.|_|\s|\d|\/)*>*)/)
			{
				my $te=$1;
				#print "$1\n";
			#	my @a1=split(/\s{2,}/,$te);
			#	if($a1[0]=~/^o*\s*<*(\w|-|\.|_|\s|\d)*>*/)
			#	{
			#		$a1[0]=~s/^o\s*//;
			#	}
				push @vals, $1;
				#print $a1[0]."\n";
			}			
			
		}
		else
		{
			next;
		}
	}
	$all_vals[0]=$in;
	$all_vals[1]=@vals;
	$obj_list{$oname}=[$in,[@vals]];
	$in++;
}
}

sub parse_rules
{
	my ($rs,$ar)=@_;
	my @arr=@{$ar};
	my $str="";
	foreach my$l(@arr)
	{
	$str=$str.$l;
	}

	my @par1=split(/\n\n/,$str);
	#print $#par1;
	foreach $l(@par1)
	{
		my @a=split(/\n/,$l);	
		my ($rnum,$from,$to,$port);
		#@a=&treat(@a);
		foreach $m(@a)
		{
			if($m=~/\s{4,5}(\d+)/)
			{
				$rnum=$1;
				#print "$rnum";
			}
			if($m=~/\s{9,11}from (.*)/)
			{
				$from=$1;
			}
			if($m=~/\s{9,13}to (\s*<*(\w|-|\.|_|\s|\d|:)*>*)(\d|\s)*/)
			{
				my $te=$1;
				if($te=~/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
				{
					$to=$1;
					my @b1=split(/\.\d{1,3}\s/,$m);
					#print $#b1."\n";
					$port=$b1[1];
					next;
				}
				else
				{
					my @s1=split(/\s/,$te);
					$to=="";
					$port="";
					for(my $i=0;$i<=$#s1;$i++)
					{
						if($s1[$i]=~/\d+:\d+/)
						{
							$port=$port.$s1[$i];
							next;
						}
						if($s1[$i]=~/\D+/)
						{
							$to=$to.$s1[$i];
						}
						else
						{
							$port=	$port.$s1[$i]." ";
						}
					}
				}
			}
		}
		#print "$rnum\t$from\t$to\t$port\n";
		if($rs eq 'outbound')
		{
			$out_rulemap{$rnum}=[$from,$to,$port];
		}
		if($rs eq 'passthrough')
		{
			$pt_rulemap{$rnum}=[$from,$to,$port];
		}
	}
}


sub create_ancestor
{
	foreach $k1(keys %obj_list)
	{
		@res=();
		&ances($k1);
		#print "$k1\n";
		#print "$k1\t@res\n";
		#last;
		my %seen;
		$seen{$_}++ for @res;
		my @unique = keys %seen;
		$obj_anc{$k1}=[@unique];
	}
}

#print Dumper(\%obj_list);
#my @par=&get_parent("UKWATPSACNS01");
#print @par;
#@res=();
#&ances("UKWATPSACNS01");
#print @res;
#print Dumper(\%obj_anc);
#print Dumper(\%pt_rulemap);
#print Dumper(\%out_rulemap);
#print sort keys %out_rulemap;
#&unused_object();

print "\n\n \tRedundant Rules\n";
print "\n \t=================\n\n";
foreach $i(sort keys %pt_rulemap)
{
my @redun=&find_redundant($i,'passthrough');
print "\nPassthrough Redundant Rules for rule# $i : @redun";
}

foreach $i(sort keys %out_rulemap)
{
my @redun=&find_redundant($i,'outbound');
print "\nOutbound Redundant Rules for rule# $i : @redun";
}

print "\n\n \tReverse Rules\n";
print "\n \t=================\n\n";
&reverse();
print "\n\n \tDuplicate Rules\n";
print "\n \t=================\n\n";
duplicate( );
print Dumper(\%dup_pair);
print "\n\n \tClear Text Rules\n";
print "\n \t=================\n\n";
&clearprot();
print "\n\n \tNetwork Access Rules\n";
print "\n \t=================\n\n";
&network_access('passthrough');
print "\n\n \tUnused Objects\n";
print "\n \t=================\n\n";
&unused_object();


sub ances
{
	my ($p1)=@_;
	my (@p2)=();
	$ind=0;
	@p2=get_parent($p1);
	#print "@p2\n";
	if($#p2!=-1)
	{
		foreach $l1(@p2)
		{
			#print $l1;
			push @res,$l1;
			&ances($l1);
		}
	}
}

#print @par;



sub ret_arr
{
my ($b,$e,$name) = @_;
#print "$b\t--$e\n";
my $FILE=$path1;
open FILE,$FILE or die "Cannot open $FILE for read :$!";
my @arr=();
my $l=0;
my $m=0;
  while(<FILE>)
  {

    if($m==1)
    {
      if($_  =~ /\Q$e\E/)
      {
        #print $_;
        #last;
        return @arr;
      }

      $arr[$l]=$_;
      #print "$l\t--\t$_\n";
      $l+=1;
    }

    if($_ =~ /^$b/)
    {
      $m=1;
      #print;
    }
  }
close FILE;
  if($m==0)
  {
    return @arr;
  }
}


sub treat
{
  my @ar=@_;
  my @tmp;
  my $flag=0;
  my $i=0;
  foreach (@ar)
  {
    s/(-|\s)+//;
    s/(\w|\s)+//;
    if($_=~/\S+/)
    {
      $tmp[$i]=$_;
      $i++;
    }
  }
  return @tmp;
}


sub get_parent
{
my ($an)=@_;
#print $an;
my @found=();
	foreach $k(keys %obj_list)
	{
	if($k eq $an)
	{
		next;
	}
	my $s2= $obj_list{$k};
	my @s3=@{$s2};
	my $s4=$s3[1];
	my @s5=@{$s4};	
		foreach $l(@s5)
		{
			#print $l;
			if($l=~/$an/)
			{
				push(@found,$k);
				last;
			}
		}
	}
return @found;
}


sub find_redundant
{
	my ($l1,$l2)=@_;
	my @red=();
	#print "$l1\n";
	if($l2 eq 'passthrough')
	{
		$an=$l1;
			my $a1=$pt_rulemap{$an};
			my @a2=@{$a1};
			my $ant=$a2[0];
			my $cons=$a2[1];
			#print @a2;
			#print "\n$ant -- $cons\n";
			my $aanc=$obj_anc{$ant};
			my $canc=$obj_anc{$cons};
			my @a_anc=@{$aanc};
			my @c_anc=@{$canc};
			push @a_anc, $ant;
			push @c_anc, $cons;
			#print "\n Antecedant ancestor: @a_anc";
			#print "\n Consequant ancestor: @c_anc";
			my @rules=&get_rules(\@a_anc,$l2);
			#print "\n@rules";
			foreach $k1(@rules)
			{
			my $a1=$pt_rulemap{$k1};
			my @a2=@{$a1};
			my $ant=$a2[0];
			my $cons=$a2[1];
			if($k1 eq $l1)
			{
				next;
			}
				foreach $ca(@c_anc)
				{
				
					#print "\n$ca\t$cons";
					if($ca eq $cons)
					{
						push @red, $k1;
						#print 'sdfsefs';
					}
				}
			#print @a2;
			#print "\n$k1 -- $ant -- $cons\n";				
			}
	}
	if($l2 eq 'outbound')
	{
		$an=$l1;
			my $a1=$out_rulemap{$an};
			my @a2=@{$a1};
			my $ant=$a2[0];
			my $cons=$a2[1];
			#print @a2;
			#print "\n$ant -- $cons\n";
			my $aanc=$obj_anc{$ant};
			my $canc=$obj_anc{$cons};
			my @a_anc=@{$aanc};
			my @c_anc=@{$canc};
			push @a_anc, $ant;
			push @c_anc, $cons;
			#print "\n Antecedant ancestor: @a_anc";
			#print "\n Consequant ancestor: @c_anc";
			my @rules=&get_rules(\@a_anc,$l2);
			#print "\n@rules";
			foreach $k1(@rules)
			{
			my $a1=$out_rulemap{$k1};
			my @a2=@{$a1};
			my $ant=$a2[0];
			my $cons=$a2[1];
			if($k1 eq $l1)
			{
				next;
			}
				foreach $ca(@c_anc)
				{
				
					#print "\n$ca\t$cons";
					if($ca eq $cons)
					{
						push @red, $k1;
						#print 'sdfsefs';
					}
				}
			#print @a2;
			#print "\n$k1 -- $ant -- $cons\n";				
			}
	}
	return @red;
}


sub get_rules
{
	my ($m1,$l2)=@_;
	my (@ar1)=@{$m1};
	#print "\nGet_Rules: @ar1";
	my @resp;
	if($l2 eq 'passthrough')
	{
	foreach $l1(@ar1)
	{
		foreach $an(keys %pt_rulemap)
		{
			my $a1=$pt_rulemap{$an};
			my @a2=@{$a1};
			if($l1 eq $a2[0])
			{
				#print "$an\n";
				push @resp, $an;
			}
		}
	}	
	}
	if($l2 eq 'outbound')
	{
	foreach $l1(@ar1)
	{
		foreach $an(keys %out_rulemap)
		{
			my $a1=$out_rulemap{$an};
			my @a2=@{$a1};
			if($l1 eq $a2[0])
			{
				#print "$an\n";
				push @resp, $an;
			}
		}
	}	
	}
	return @resp;
}


sub printobj
{
foreach $l(keys %obj_list)
{
	my $s2= $obj_list{$l};
	my @s3=@{$s2};
	my $s4=$s3[0];
	my @s5=@{$s3[1]};	
	print "\t$s4\t--\t$l\n"; 
}
}

sub reverse
{
	foreach $an(sort keys %pt_rulemap)
	{
		my $a1=$pt_rulemap{$an};
		my @a2=@{$a1};
		foreach $am(sort keys %pt_rulemap)
		{
			if($an>$am)
			{
				next;
			}
			my $a3=$pt_rulemap{$am};
			my @a4=@{$a3};
			if(($a2[0] eq $a4[1]) && ($a2[1] eq $a4[0]))
			{
				#print "\nReverse Rule pairs: $an -- $am";
				$rev_pair{$an}=$am;
				last;
			}
		}	
	}
}


sub duplicate
{
	foreach $an(sort keys %pt_rulemap)
	{
		my $a1=$pt_rulemap{$an};
		my @a2=@{$a1};
		foreach $am(sort keys %pt_rulemap)
		{
			if($an>=$am)
			{
				next;
			}
			my $a3=$pt_rulemap{$am};
			my @a4=@{$a3};
			if(($a2[0] eq $a4[0]) && ($a2[1] eq $a4[1]) && ($a2[2] eq $a4[2]))
			{
				#print "\nReverse Rule pairs: $an -- $am";
				$dup_pair{$an}=[$am,'passthrough'];
				last;
			}
		}	
		foreach $am(sort keys %out_rulemap)
		{
			my $a3=$out_rulemap{$am};
			my @a4=@{$a3};
			if(($a2[0] eq $a4[0]) && ($a2[1] eq $a4[1]))
			{
				$dup_pair{$an}=[$am,'outbound'];
				last;
			}
		}	
	}
}


sub clearprot
{
		my $a1=$pt_rulemap{$an};
		my @a2=@{$a1};
		foreach $am(sort keys %pt_rulemap)
		{
			if($an>=$am)
			{
				next;
			}
			my $a3=$pt_rulemap{$am};
			my @a4=@{$a3};
			my @b1=split(/\s/,$a4[2]);
			#print "$b1\n";
			foreach my $er(@b1)
			{
			if($$er==80 ||$er==21||$er==23)
			{
				print "\n Passthrough Rule #: $am \t@b1";
				last;
			}
			}
		}	
		foreach $am(sort keys %out_rulemap)
		{
			my $a3=$out_rulemap{$am};
			my @a4=@{$a3};
			my @b1=split(/\s/,$a4[2]);
			foreach my $ew(@b1)
			{
			if($ew==80 ||$ew==21||$ew==23)
			{
				print "\n Outbound Rule #: $am";
				#print "\n$a4[0]\t$a4[1]\t$a4[2]";
			}
			}
		}	

}

sub network_access
{
	my ($l)=@_;
	my @seed;
	if($l eq 'passthrough')
	{
		foreach $t(keys %obj_list)
		{
			my $s2= $obj_list{$t};
			my @s3=@{$s2};
			my $s4=$s3[1];
			my @s5=@{$s4};	
			foreach my $m(@s5)
			{
			if ($m=~/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\//)
			{
				push @seed,$t;
				last;
			}
			}
		}
	}
	foreach $r(@seed)
	{
		my $aanc=$obj_anc{$r};
		my @a_anc=@{$aanc};
		#print "\n$r -- @a_anc";
		push @a_anc,$r;
		
		foreach $l1(@a_anc)
		{
			foreach $an(keys %pt_rulemap)
			{
				my $a1=$pt_rulemap{$an};
				my @a2=@{$a1};
				if($l1 eq $a2[0]||$l1 eq $a2[1])
				{
					print "$r\t--\t$an\t--\tpassthrough\n";
				}
			}
		}	
		foreach $l1(@a_anc)
		{
			foreach $an(keys %out_rulemap)
			{
				my $a1=$out_rulemap{$an};
				my @a2=@{$a1};
				if($l1 eq $a2[0]||$l1 eq $a2[1])
				{
					print "$r\t--\t$an\t--\toutbound\n";
				}
			}
		}	
	}
	
	print "\n\nall n\/w obj";
	foreach my $e(@seed)
	{
		print "\n$e";
	}
}


sub unused_object
{
	my $in=0;
	foreach $t(keys %obj_list)
	{
		$flag=0;
		$in ++;
			my $aanc=$obj_anc{$t};
			my @a_anc=@{$aanc};
			my $no=$#a_anc;
		foreach $an(keys %pt_rulemap)
		{
			my $a1=$pt_rulemap{$an};
			my @a2=@{$a1};
			if($t eq $a2[0]||$t eq $a2[1])
			{
				#print "$r\t--\t$an\n";
				$flag=1;
				last;
			}
		}	
		foreach $an(keys %out_rulemap)
		{
			my $a1=$out_rulemap{$an};
			my @a2=@{$a1};
			if($t eq $a2[0]||$t eq $a2[1])
			{
				#print "$r\t--\t$an\n";
				$flag=1;
				last;
			}
		}	
		if($flag==0 && $no==-1)
		{
			print "\n$in - Unused Object: $t";
		}
	}
}