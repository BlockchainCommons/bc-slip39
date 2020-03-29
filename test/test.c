#include <stdio.h>
#include <assert.h>
#include <strings.h>
#include "../src/bc-slip39.h"
#include "test-utils.h"

static void test_string_for_word() {
  assert(equal_strings(slip39_string_for_word(0), "academic"));
  assert(equal_strings(slip39_string_for_word(512), "leader"));
  assert(equal_strings(slip39_string_for_word(1023), "zero"));
  assert(equal_strings(slip39_string_for_word(1024), ""));
}

static void test_word_for_string() {
  assert(slip39_word_for_string("academic") == 0);
  assert(slip39_word_for_string("leader") == 512);
  assert(slip39_word_for_string("zero") == 1023);
  assert(slip39_word_for_string("FOOBAR") < 0);
}

static void test_counts() {
  size_t byte_counts[] = {0, 2, 6, 8, 10, 20, 100, 102};
  size_t word_counts[] = {0, 2, 5, 7, 8, 16, 80, 82};
  for(int i = 0; i < 8; i++) {
    assert(slip39_word_count_for_bytes(byte_counts[i]) == word_counts[i]);
    assert(slip39_byte_count_for_words(word_counts[i]) == byte_counts[i]);
  }
}

static void test_words() {
  uint8_t data[] = {0x00, 0x01, 0x02, 0x03, 0xaa, 0xff, 0xff, 0xee};
  size_t data_len = 8;
  size_t words_len = slip39_word_count_for_bytes(data_len);
  uint16_t words[] = {0, 0, 258, 14, 687, 1023, 1006};

  uint16_t* output_words = alloc_uint16_buffer(words_len, 0xffff);
  size_t words_written = slip39_words_for_data(data, data_len, output_words, words_len);
  assert(equal_uint16_buffers(words, words_len, output_words, words_written));
  free(output_words);

  uint8_t* output_data = alloc_uint8_buffer(data_len, 0xee);
  size_t data_written = slip39_data_for_words(words, words_len, output_data, data_len);
  assert(equal_uint8_buffers(data, data_len, output_data, data_written));
  free(output_data);
}

static void test_strings() {
  uint16_t words[] = {0, 0, 258, 14, 687, 1023, 1006};
  size_t words_len = 7;
  char* string = slip39_strings_for_words(words, words_len);
  char* expected_string = "academic academic eclipse advocate predator zero wine";
  assert(equal_strings(string, expected_string));
  uint16_t output_words[words_len];
  size_t words_written = slip39_words_for_strings(string, output_words, words_len);
  assert(equal_uint16_buffers(words, words_len, output_words, words_written));
  free(string);
}

static void test_generate_and_combine() {
  char* secret = "totally secret!";
  size_t secret_len = strlen(secret) + 1;
  uint8_t* secret_data = (uint8_t*)secret;

  char* password = "";

  uint8_t share_threshold = 3;
  uint8_t share_count = 5;

  uint8_t group_threshold = 1;
  uint8_t group_count = 1;
  group_descriptor group = { share_threshold, share_count, NULL };
  group_descriptor groups[] = { group };

  uint8_t iteration_exponent = 0;

  uint32_t words_in_each_share = 0;
  size_t shares_buffer_size = 1024;
  uint16_t shares_buffer[shares_buffer_size];

  int result = slip39_generate(
    group_threshold,
    groups,
    group_count,
    secret_data,
    secret_len,
    password,
    iteration_exponent,
    &words_in_each_share,
    shares_buffer,
    shares_buffer_size,
    fake_random
  );
  assert(result == share_count);
  // printf("%d\n", share_count);
  char* strings[share_count];
  for(int i = 0; i < share_count; i++) {
    uint16_t* words = shares_buffer + (i * words_in_each_share);
    strings[i] = slip39_strings_for_words(words, words_in_each_share);
  }

  // for(int i = 0; i < share_count; i++) {
  //   printf("%s\n", strings[i]);
  // }

  int selected_share_indexes[] = {1, 3, 4};
  size_t selected_shares_len = 3;
  uint16_t* selected_shares_words[selected_shares_len];
  for(int i = 0; i < selected_shares_len; i++) {
    uint16_t* words_buf = alloc_uint16_buffer(words_in_each_share, 0);
    selected_shares_words[i] = words_buf;
    int selected_share_index = selected_share_indexes[i];
    char* string = strings[selected_share_index];
    slip39_words_for_strings(string, words_buf, words_in_each_share);
  }

  size_t output_secret_data_len = 1024;
  uint8_t output_secret_data[output_secret_data_len];

  int combine_result = slip39_combine(
    (const uint16_t **)selected_shares_words,
    words_in_each_share,
    selected_shares_len,
    password,
    NULL,
    output_secret_data,
    output_secret_data_len
  );

  assert(combine_result == secret_len);

  char* output_secret = (char*)output_secret_data;
  assert(equal_strings(secret, output_secret));

  for(int i = 0; i < selected_shares_len; i++) {
    free(selected_shares_words[i]);
  }

  for(int i = 0; i < share_count; i++) {
    free(strings[i]);
  }
}

static bool _test_combine(const char** shares_strings, size_t shares_len, char* expected) {
  uint16_t* shares_words[shares_len];
  size_t words_in_each_share = 0;
  for(int i = 0; i < shares_len; i++) {
    size_t words_buf_len = 100;
    uint16_t words_buf[words_buf_len];
    words_in_each_share = slip39_words_for_strings(shares_strings[i], words_buf, words_buf_len);
    uint16_t* share_words = alloc_uint16_buffer(words_in_each_share, 0);
    shares_words[i] = share_words;
    for(int j = 0; j < words_in_each_share; j++) {
      share_words[j] = words_buf[j];
    }
  }

  size_t output_secret_data_len = 1024;
  uint8_t output_secret_data[output_secret_data_len];

  int combine_result = slip39_combine(
    (const uint16_t **)shares_words,
    words_in_each_share,
    shares_len,
    "TREZOR",
    NULL,
    output_secret_data,
    output_secret_data_len
  );

  if(combine_result > 0) {
    char* output_secret = data_to_hex(output_secret_data, combine_result);
    if(!equal_strings(expected, output_secret)) {
      return false;
    }
    free(output_secret);
  } else {
    if(expected != NULL) {
      return false;
    }
  }

  for(int i = 0; i < shares_len; i++) {
    free(shares_words[i]);
  }
  return true;
}

static void test_combine() {
  // 1. Valid mnemonic without sharing (128 bits)
  assert(_test_combine((const char*[]) {
      "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard"
    }, 1,
    "bb54aac4b89dc868ba37d9cc21b2cece")
  );

  // 2. Mnemonic with invalid checksum (128 bits)
  assert(_test_combine((const char*[]) {
      "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney"
    }, 1,
    NULL)
  );

  // 3. Mnemonic with invalid padding (128 bits)
  assert(_test_combine((const char*[]) {
      "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness"
    }, 1,
    NULL)
  );

  // 4. Basic sharing 2-of-3 (128 bits)
  assert(_test_combine((const char*[]) {
      "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
      "shadow pistol academic acid actress prayer class unknown daughter sweater depict flip twice unkind craft early superior advocate guest smoking"
    }, 2,
    "b43ceb7e57a0ea8766221624d01b0864")
  );

  // 5. Basic sharing 2-of-3 (128 bits)
  assert(_test_combine((const char*[]) {
      "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed"
    }, 1,
    NULL)
  );

  // 6. Mnemonics with different identifiers (128 bits)
  assert(_test_combine((const char*[]) {
      "adequate smoking academic acid debut wine petition glen cluster slow rhyme slow simple epidemic rumor junk tracks treat olympic tolerate",
      "adequate stay academic agency agency formal party ting frequent learn upstairs remember smear leaf damage anatomy ladle market hush corner"
    }, 2,
    NULL)
  );

  // 7. Mnemonics with different iteration exponents (128 bits)
  assert(_test_combine((const char*[]) {
      "peasant leaves academic acid desert exact olympic math alive axle trial tackle drug deny decent smear dominant desert bucket remind",
      "peasant leader academic agency cultural blessing percent network envelope medal junk primary human pumps jacket fragment payroll ticket evoke voice"
    }, 2,
    NULL)
  );

  // 8. Mnemonics with mismatching group thresholds (128 bits)
  assert(_test_combine((const char*[]) {
      "liberty category beard echo animal fawn temple briefing math username various wolf aviation fancy visual holy thunder yelp helpful payment",
      "liberty category beard email beyond should fancy romp founder easel pink holy hairy romp loyalty material victim owner toxic custody",
      "liberty category academic easy being hazard crush diminish oral lizard reaction cluster force dilemma deploy force club veteran expect photo"
    }, 3,
    NULL)
  );

  // 9. Mnemonics with mismatching group counts (128 bits)
  assert(_test_combine((const char*[]) {
      "average senior academic leaf broken teacher expect surface hour capture obesity desire negative dynamic dominant pistol mineral mailman iris aide",
      "average senior academic leaf broken teacher expect surface hour capture obesity desire negative dynamic dominant pistol mineral mailman iris aide"
    }, 2,
    NULL)
  );

  // 10. Mnemonics with greater group threshold than group counts (128 bits)
  assert(_test_combine((const char*[]) {
      "music husband acrobat acid artist finance center either graduate swimming object bike medical clothes station aspect spider maiden bulb welcome",
      "music husband acrobat agency advance hunting bike corner density careful material civil evil tactics remind hawk discuss hobo voice rainbow",
      "music husband beard academic black tricycle clock mayor estimate level photo episode exclude ecology papa source amazing salt verify divorce"
    }, 3,
    NULL)
  );

  // 11. Mnemonics with duplicate member indices (128 bits)
  assert(_test_combine((const char*[]) {
      "device stay academic always dive coal antenna adult black exceed stadium herald advance soldier busy dryer daughter evaluate minister laser",
      "device stay academic always dwarf afraid robin gravity crunch adjust soul branch walnut coastal dream costume scholar mortgage mountain pumps"
    }, 2,
    NULL)
  );

  // 12. Mnemonics with mismatching member thresholds (128 bits)
  assert(_test_combine((const char*[]) {
      "hour painting academic academic device formal evoke guitar random modern justice filter withdraw trouble identify mailman insect general cover oven",
      "hour painting academic agency artist again daisy capital beaver fiber much enjoy suitable symbolic identify photo editor romp float echo"
    }, 2,
    NULL)
  );

  // 13. Mnemonics giving an invalid digest (128 bits)
  assert(_test_combine((const char*[]) {
      "guilt walnut academic acid deliver remove equip listen vampire tactics nylon rhythm failure husband fatigue alive blind enemy teaspoon rebound",
      "guilt walnut academic agency brave hamster hobo declare herd taste alpha slim criminal mild arcade formal romp branch pink ambition"
    }, 2,
    NULL)
  );

  // 14. Insufficient number of groups (128 bits, case 1)
  assert(_test_combine((const char*[]) {
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice"
    }, 1,
    NULL)
  );

  // 15. Insufficient number of groups (128 bits, case 2)
  assert(_test_combine((const char*[]) {
      "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join",
      "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter"
    }, 2,
    NULL)
  );

  // 16. Threshold number of groups, but insufficient number of members in one group (128 bits)
  assert(_test_combine((const char*[]) {
      "eraser senior decision shadow artist work morning estate greatest pipeline plan ting petition forget hormone flexible general goat admit surface",
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice"
    }, 2,
    NULL)
  );

  // 17. Threshold number of groups and members in each group (128 bits, case 1)
  assert(_test_combine((const char*[]) {
      "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",
      "eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup",
      "eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces",
      "eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate",
      "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing"
    }, 5,
    "7c3397a292a5941682d7a4ae2d898d11")
  );

  // 18. Threshold number of groups and members in each group (128 bits, case 2)
  assert(_test_combine((const char*[]) {
      "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing",
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
      "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join"
    }, 3,
    "7c3397a292a5941682d7a4ae2d898d11")
  );

  // 19. Threshold number of groups and members in each group (128 bits, case 3)
  assert(_test_combine((const char*[]) {
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
      "eraser senior acrobat romp bishop medical gesture pumps secret alive ultimate quarter priest subject class dictate spew material endless market"
    }, 2,
    "7c3397a292a5941682d7a4ae2d898d11")
  );

  // 20. Valid mnemonic without sharing (256 bits)
  assert(_test_combine((const char*[]) {
      "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect luck"
    }, 1,
    "989baf9dcaad5b10ca33dfd8cc75e42477025dce88ae83e75a230086a0e00e92")
  );

  // 21. Mnemonic with invalid checksum (256 bits)
  assert(_test_combine((const char*[]) {
      "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect lunar"
    }, 1,
    NULL)
  );

  // 22. Mnemonic with invalid padding (256 bits)
  assert(_test_combine((const char*[]) {
      "theory painting academic academic campus sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips facility obtain sister"
    }, 1,
    NULL)
  );

  // 23. Basic sharing 2-of-3 (256 bits)
  assert(_test_combine((const char*[]) {
      "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap",
      "humidity disease academic agency actress jacket gross physics cylinder solution fake mortgage benefit public busy prepare sharp friar change work slow purchase ruler again tricycle involve viral wireless mixture anatomy desert cargo upgrade"
    }, 2,
    "c938b319067687e990e05e0da0ecce1278f75ff58d9853f19dcaeed5de104aae")
  );

  // 24. Basic sharing 2-of-3 (256 bits)
  assert(_test_combine((const char*[]) {
      "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap"
    }, 1,
    NULL)
  );

  // 25. Mnemonics with different identifiers (256 bits)
  assert(_test_combine((const char*[]) {
      "smear husband academic acid deadline scene venture distance dive overall parking bracelet elevator justice echo burning oven chest duke nylon",
      "smear isolate academic agency alpha mandate decorate burden recover guard exercise fatal force syndrome fumes thank guest drift dramatic mule"
    }, 2,
    NULL)
  );

  // 26. Mnemonics with different iteration exponents (256 bits)
  assert(_test_combine((const char*[]) {
      "finger trash academic acid average priority dish revenue academic hospital spirit western ocean fact calcium syndrome greatest plan losing dictate",
      "finger traffic academic agency building lilac deny paces subject threaten diploma eclipse window unknown health slim piece dragon focus smirk"
    }, 2,
    NULL)
  );

  // 27. Mnemonics with mismatching group thresholds (256 bits)
  assert(_test_combine((const char*[]) {
      "flavor pink beard echo depart forbid retreat become frost helpful juice unwrap reunion credit math burning spine black capital lair",
      "flavor pink beard email diet teaspoon freshman identify document rebound cricket prune headset loyalty smell emission skin often square rebound",
      "flavor pink academic easy credit cage raisin crazy closet lobe mobile become drink human tactics valuable hand capture sympathy finger"
    }, 3,
    NULL)
  );

  // 28. Mnemonics with mismatching group counts (256 bits)
  assert(_test_combine((const char*[]) {
      "column flea academic leaf debut extra surface slow timber husky lawsuit game behavior husky swimming already paper episode tricycle scroll",
      "column flea academic agency blessing garbage party software stadium verify silent umbrella therapy decorate chemical erode dramatic eclipse replace apart"
    }, 2,
    NULL)
  );

  // 29. Mnemonics with greater group threshold than group counts (256 bits)
  assert(_test_combine((const char*[]) {
      "smirk pink acrobat acid auction wireless impulse spine sprinkle fortune clogs elbow guest hush loyalty crush dictate tracks airport talent",
      "smirk pink acrobat agency dwarf emperor ajar organize legs slice harvest plastic dynamic style mobile float bulb health coding credit",
      "smirk pink beard academic alto strategy carve shame language rapids ruin smart location spray training acquire eraser endorse submit peaceful"
    }, 3,
    NULL)
  );

  // 30. Mnemonics with duplicate member indices (256 bits)
  assert(_test_combine((const char*[]) {
      "fishing recover academic always device craft trend snapshot gums skin downtown watch device sniff hour clock public maximum garlic born",
      "fishing recover academic always aircraft view software cradle fangs amazing package plastic evaluate intend penalty epidemic anatomy quarter cage apart"
    }, 2,
    NULL)
  );

  // 31. Mnemonics with mismatching member thresholds (256 bits)
  assert(_test_combine((const char*[]) {
      "evoke garden academic academic answer wolf scandal modern warmth station devote emerald market physics surface formal amazing aquatic gesture medical",
      "evoke garden academic agency deal revenue knit reunion decrease magazine flexible company goat repair alarm military facility clogs aide mandate"
    }, 2,
    NULL)
  );

  // 32. Mnemonics giving an invalid digest (256 bits)
  assert(_test_combine((const char*[]) {
      "river deal academic acid average forbid pistol peanut custody bike class aunt hairy merit valid flexible learn ajar very easel",
      "river deal academic agency camera amuse lungs numb isolate display smear piece traffic worthy year patrol crush fact fancy emission"
    }, 2,
    NULL)
  );

  // 33. Insufficient number of groups (256 bits, case 1)
  assert(_test_combine((const char*[]) {
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium"
    }, 1,
    NULL)
  );

  // 34. Insufficient number of groups (256 bits, case 2)
  assert(_test_combine((const char*[]) {
      "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
      "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install"
    }, 2,
    NULL)
  );

  // 35. Threshold number of groups, but insufficient number of members in one group (256 bits)
  assert(_test_combine((const char*[]) {
      "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club",
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium"
    }, 2,
    NULL)
  );

  // 36. Threshold number of groups and members in each group (256 bits, case 1)
  assert(_test_combine((const char*[]) {
      "wildlife deal ceramic round aluminum pitch goat racism employer miracle percent math decision episode dramatic editor lily prospect program scene rebuild display sympathy have single mustang junction relate often chemical society wits estate",
      "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
      "wildlife deal ceramic scatter argue equip vampire together ruin reject literary rival distance aquatic agency teammate rebound false argue miracle stay again blessing peaceful unknown cover beard acid island language debris industry idle",
      "wildlife deal ceramic snake agree voter main lecture axis kitchen physics arcade velvet spine idea scroll promise platform firm sharp patrol divorce ancestor fantasy forbid goat ajar believe swimming cowboy symbolic plastic spelling",
      "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club"
    }, 5,
    "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b")
  );

  // 37. Threshold number of groups and members in each group (256 bits, case 2)
  assert(_test_combine((const char*[]) {
      "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
      "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install"
    }, 3,
    "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b")
  );

  // 38. Threshold number of groups and members in each group (256 bits, case 3)
  assert(_test_combine((const char*[]) {
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
      "wildlife deal acrobat romp anxiety axis starting require metric flexible geology game drove editor edge screw helpful have huge holy making pitch unknown carve holiday numb glasses survive already tenant adapt goat fangs"
    }, 2,
    "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b")
  );

  // 39. Mnemonic with insufficient length
  assert(_test_combine((const char*[]) {
      "junk necklace academic academic acne isolate join hesitate lunar roster dough calcium chemical ladybug amount mobile glasses verify cylinder"
    }, 1,
    NULL)
  );

  // 40. Mnemonic with invalid master secret length
  assert(_test_combine((const char*[]) {
      "fraction necklace academic academic award teammate mouse regular testify coding building member verdict purchase blind camera duration email prepare spirit quarter"
    }, 1,
    NULL)
  );
}

#if !defined(ARDUINO)
int main() {
  test_string_for_word();
  test_word_for_string();
  test_counts();
  test_words();
  test_strings();
  test_generate_and_combine();
  test_combine();
}
#endif // !defined(ARDUINO)
