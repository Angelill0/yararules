rule isfb_gozi_V217039_C2_memory {
     meta:
      description = "Gozi C217039 C2 mem explorer.exe"
      author = "@Angelill0 -  Angel Alonso Parrizas"
      date = "2018-11-19"

   strings:
        //$s1 = /soft=\S+/
        $s1 = /soft=\S+&version=\S+&user=\S+&server=\S+&id=\S+/  // Gozi V2
        $s2 = /soft=\S+&user=\S+&server=\S+&id=\S+/ // Gozi V2
        $s3 = /soft=\S+&version=\S+&user=\S+&group=\S+&id=\S+/  //Gozi V3

   condition:
        $s1  or $s2 or  $s3

}
~
~
