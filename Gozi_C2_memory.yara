rule Gozi_IFSB_C2_memory {
     meta:
      description = "Gozi C2 memory"
      author = "@Angelill0 -  Angel Alonso Parrizas"
      date = "2018-11-29"

   strings:
        //$s1 = /soft=\S+/
        $s1 = /soft=\S+&version=\S+&user=\S+&server=\S+&id=\S+/  // Gozi V2
        $s2 = /soft=\S+&user=\S+&server=\S+&id=\S+/ // Gozi V2
        $s3 = /soft=\S+&version=\S+&user=\S+&group=\S+&id=\S+/  //Gozi V3

   condition:
        $s1  or $s2 or  $s3

}

