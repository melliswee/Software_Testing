# Ohjelmistotestaus - Teoriatenttiin kertaaminen

Ohjelmistotestaus- kurssin tentti on paperitentti, joka on suomeksi. Testaukseen kieli on englanti ja materiaalit ovat englanniksi, hyödynnän materiaalin kääntämistä kertaamisena tenttiin. Alkuperäisen englanninkielisen materiaalin on tehnyt Raine Kauppinen kurssille Software Testing (SOF012AS3AE).

## Testaaminen osana laadunvarmistusta ja -kehitystä

Ohjelmiston laadunvarmistus sisältää mm.:

* staattinen testaus (esim. koodin katselmointi)
* ohjelmistotestaus
* dynaaminen testaus (esim. yksikkötestaus)

Ohjelmistotestaus on tärkeää, koska:

* ohjelmistossa on todennäköisesti vikoja (defects), koska vaatimukset, dokumentit ja ohjelmiston on kirjoittanut ihminen
* infrastruktuuri voi olla monimutkainen, teknologiat muuttuneita, useampi systeemi on vuorovaikutuksessa keskenään
* viat (defects) voivat olla todella kalliita
* sopimukset, laki tai teollisuuden omat vaatimukset vaativat niitä

Hyvän testauksen piirteitä ovat:

* Jokaiselle kehitystoimelle (development activity) on vastaava testaustoimi (testing activity) (tyyppi).
* Jokaisella testityypillä on tarkkaanmääritellyt (specific) tavoitteet (objectives).
* Testien analysointi ja suunnittelu tietylle testityypille pitäisi aloittaa ennen tai yhtäaikaisesti siihen liittyvän kehitystoimen kanssa.
* Testaajien pitäisi olla mukana heti kun luonnos on saatavilla ja suunnitelmia (plan) ja designia käydään läpi.  
* Tärkein ohjaava sääntö: testataan aikaisin ja usein.

## Testaamisen yleiset perusperiaatteet

* Testaaminen osoittaa vikojen (defects) läsnäolon, mutta ei todista viattomuutta. Ohjelmiston laadun arvioimiseksi arvioidaan siis sekä ohjelmiston laatua että testtauksen laatua.
* Kaiken testaaminen ei ole tehtävissä, koska testien määrä kasvaa nopeasti. Siksi meidän on priorisoitava ja arvioitava, milloin testausta on tehty tarpeeksi. Päätös riippuu esimerkiksi testausstrategiasta ja määritellyistä hyväksymiskriteereistä.
* Testauksen pitää kehittyä ajan kuluessa, koska lopulta vanhat testit eivät enää löydä uusia vikoja tai ne eivät enää sovi kehittyvään ohjelmistoon. Testejä pitää siis muokata ja lisätä ajan kuluessa. Lisäksi on voitava osoittaa mitä osaa ohjelmistosta kukin testi testaa (jäljitettävyys = traceability).
* Testaaminen on asiayhteysriippuvaista. Eri tarkoituksiin tarkoitettujen ohjelmistojen testaaminen on erilaista (vrt. nettisivu vs. avaruussukkula). Siten kriittisimpiä osia ohjelmistosta testataan eniten.

## Ohjelmistotestauksen kaksi puolta

* Odotetun testaaminen:

    * Onnellisten päivien testaaminen eli ohjelmistoa käytetään kuten on tarkoitettu. Ohjelmistolle annetaan sallittuja syötteitä (positiiviset testit) ja odotettuja kiellettyjä syötteitä ja virheitä.
    * Nämä testit on helppo suunnitella ja toteuttaa ja arvioida, jos vaatimukset, suunnittely ja määrittelyt on tehty hyvin.
    * Systemaattiset testauskäytänteet sopivat tähän hyvin.

* Odottamattoman testaaminen:

    * Epätyypillisen tai tuntemattoman käytön testaaminen, esimerkiksi ohjelmiston rikkomisyritykset (injektiot tai XSS).
    * Testaajan tietotaidon ja kokemuksen tai keskittymisen tiettyyn testaamiseen sopivat tähän.

## Tärkeät termit: vika (error), vika (defect) ja vika (failure)

* Error = ihmisen toiminta joka tuottaa väärän tuloksen
    * Toiminta: Kehittäjä unohti toteuttaa taaksepäin yhteensopivuuden.
* Defect (bug, fault) = epätäydellisyys tai puuttellisuus tuotteessa, minkä takia vaatimuksia ja määrityksiä ei saavuteta
    * Ohjelmiston tila: Taaksepäinsopivuus puuttuu.
    * Vika voi aiheuttaa epäonnistumisen.
* Failure = tapahtuma, jossa komponentti tai systeemi ei suoriudu halutusta toiminnosta
    * Tapahtuma: En voi enää avata tiedostoa.

## Tärkeät termit: tarkistus (verification), kelpuutus (validation) ja testaaminen (testing)

* Tarkistus = Verification: Varmistus tutkimalla, että vaatimukset ovat todistetusti täytetty. Eli onko ohjelmistoa tehty oikein.
* Kelpuutus = Validation: Varmistus tutkimalla, että onko tietyn toiminnallisuuden vaatimukset tai käyttötarkoitus ovat tulleet täytetyiksi. Eli onko rakennettu oikeaa ohjelmistoa.
* Testaaminen: Prosessi, joka koostuu kaikista elinkaaren toiminnoista, sekä staattisista että dynaamisista, ja jotka liittyvät ohjelmistotuotteiden tms. suunnitteluun, valmisteluun ja arviointiin, jotta voitaisiin päättää, että ne täyttävät määritellyt vaatimukset, sopivat tarkoitukseensa ja löytävät viat.

## TUNNILTA: Tärkeät termit: Integrointi vs. Integraatio (molemmat eng. integration)
* Integrointi: on komponentteja eli pieniä kokonaisuuksia tietojärjestelmän sisällä -> tehdään yksikkötestejä -> on esim. komponentti jossa on monia luokkia -> esim. luokkien välillä tehdään integrointitestejä eli onko osasten liittäminen toisiinsa onnistunut
    * Testikattavuus luokalle, komponentille, tietojärjestelmälle
    * "elefantti syödään paloissa"
* Integraatio: esim. järjestelmätestauksen yhteydessä tehdään tietojärjestelmien (esim. tietojärjestelmä a:n ja b:n välillä, esim. niiden välisiä input ja output dataa) välisiä integraatiotestejä

## Ohjelmistotestauksen mallit ja viitekehykset (frameworks): V-malli ja testauspyramidi sekä Agile testausneljännekset

* V-malli: 
    * **testien suunnittelu**: -> **testien toteutus**:
        * 1. vaatimusmäärittely ->  8. hyväksymistestaus
        * 2. korkean tason suunnittelu -> 7. systeemitestaus
        * 3. yksityiskohtainen suunnittelu -> 6. integraatiotestaus
        * 4. Koodi -> 5. yksikkötestaus

* Testauspyramidi:
    * yksikkötestit pohjana -> eniten eriytyneisyyttä (isolation), vähiten integraatiota, nopeampia
    * palvelutestit (service tests) keskellä
    * UI-testi (käyttöliittymätestit) huipulla -> eniten integraatiota, vähiten eriytyneisyyttä, hitaampia

* Testausneljännekset:
    * teknogia-puoleinen vs. bisnes-puoleinen
    * tiimin tukemisen puoli vs. tuotteen kritiikin puoli

    -> Q1: yksikkö- ja komponenttitestit ovat tiimiä tukevia ja teknologia-puoleisia, automatisoituja testejä <br>
    -> Q2: funktionaaliset testit, esimerkikit, tarinatestit, prototyypit ja simulaatiot ovat tiimiä tukevia ja bisnespuoleisia, automatisoituja ja manuaalisia testejä <br>
    -> Q3: etsivä testaaminen, tilanteet (scenarios), käytettävyystestaus, hyväksymistestaus (User acceptance testing), Alpha/Beta ovat tuotteen kritiikin puoleisia ja bisnes-puoleisia, manuaalisia testejä <br>
    -> Q4: suorituskykytestaus, turvallisuustestaus ja "-ility" testaus ovat tuotteen kritiikin puoleisia ja teknologia-puoleisia, työkaluilla tehtäviä testejä

## Testaustyyppejä...

* Rakenteellinen (structural) (komponentti)
    * Rakenteellisessa testauksessa testaaminen perustuu ohjelmiston rakenteeseen
    * Ohjelmiston sisäinen rakenne nähdään (koodi). Tätä kutsutaan koodipohjaiseksi tai valkolaatikko- tai lasilaatikko- testaukseksi
    * Esimerkiksi yksikkö- ja integrointitestaukset
* Toiminnallinen (functional) (end-to-end)
    * Toiminnallisessa testauksessa testaaminen perustuu määrityksen toiminnallisuuden analyysiin. Input-odotettu output. Mustalaatikko-testaus
    * Koodia ei nähdä.
    * Esimerkiksi systeemi-, hyväksymis- ja käyttöliittymätestaus
* Etsivä (exploratory) (ad hoc-tyyli)
    * Etsivä testaaminen perustuu vikojen löytämiseen, joka hyötyy testaajan tiedosta ja vaistoista. Viat, joita ei helposti löydy muilla testityypeillä.
    * Käytetään antamaan nopeaa palautetta uusista kehitetyistä ominaisuuksista, täydentämään muita testityyppejä tai antamaan pohjaa muille, muodollisemmille tai automatisoiduille, testeille
* Erikois...
    * Lisätestausta, joka valitaan ja tehdään ohjelmiston erityisominaisuuksien mukaan
    * Usein käytetään erikoistekniikoita ja työkaluja
    * Esimerkiksi suorituskyky-, käytettävyys-, turvallisuus- ja regressiotestaus
* Monia muita... 

## Tärkeitä termejä: testauspolitiikka (test policy), testistrategia (test strategy) ja testisuunnitelma peukalosäännöllä (test plan, rule of thumb)

* Testipolitiikka:
    * Organisaation runko tai pääpiirteet ohjelmistotestauksen lähestymistavalle, ja joka on usein osa organisaation laadunvarmistuspolitiikkaa
    * Määrittelee testiprosessin, testauksen, tehokkuuden ja odotetun laadun tason ja lähestymistavan sille miten testiprosessin parantamiseen suhtaudutaan nykyisissä ja entisissä, ylläpidettävissä ohjelmistoissa.
* Testistrategia:
    * Korkean tason kuvaus testitasoista ja testauksesta, jota tehdään eri tasoilla. Sisältää myös minkälainen lähestymistapa organisaatiolla on riskienhallintaan mukaanlukien riskien tunnistaminen ja riskeihin reagoimisen tavat.
    * Sisältää myös noudatettavat standardit ja yleisen testausympäristön, lähestymistavat, käytetyt mittarit, tulosten analysoimisen ja raportoimisen.
* Testisuunnitelma:
    * Dokumentti, joka kuvaa yksityiskohtaisesti laajuuden, lähestymistavan, resurssit ja aikataulun testausaktiviteeteille tietylle testauskohteelle (esim. projektille, kehityssyklin osalle tai testaustasolle).
    * Testisuunnitelma identifioi mm. testauksen kohteen, testaustehtävät, vastuuhenkilöt, testiympäristön, aloitus- ja lopetus-kriteerit (entry & exit criteria) ja mahdolliset riskit, joita varten tarvitaan vara(-utumis?)suunnitelma (contingency plan).
* Peukalosääntö, SPACE DIRT:
    * Scope
    * People
    * Approach
    * Criteria
    * Environment
<br></br>
    * Delivarables
    * Incidental
    * Risks
    * Tasks

## Tavanomaiset lähestymistavat testaamiseen

* Systemaattinen:
    * Testit suunnitellaan ja dokumentoidaan testisuunnitelmassa mahdollisimman aikaisessa vaiheessa. Testit kattavat tietyn valitun osan ohjelmistosta tietystä valitusta näkökulmasta
    * Kun testit on suoritettu, niiden testien tulokset dokumentoidaan ja raportoidaan sekä niiden testitulokset ja testikattavuus analysoidaan
* Täydentävä/vastavuoroinen (complementary)
    * Testit täydentävät toisia testejä, jotta löydetään vaikeasti löydettäviä vikoja, joita on muulla testaamisella vaikea löytää.
    * Esimerkki: etsivä testaaminen, käytettävyys, suorituskyky, turvallisuus, jotka täydentävät systemaattista testaamista.
* Testivetoinen (test driven)
    * Testit suunnitellaan, muotoillaan ja toteutetaan ennen ohjelmistoa, jota ne testaavat.
    * Testit ohjaavat ohjelmistokehitystä ja ohjelmiston osaa pidetään valmiina kun se läpäisee testit.
    * Muunnos sestemaattisesta testaamisesta.
* Riski- tai arvopohjainen
    * Testeissä keskitytään tiedettyihin riskeihin tai lisäarvoon, joka syntyy ominaisuuteen.
    * Käytetään esim. olemassa olevien testien priorisoimiseen tai uusien täydentävien testien johtamiseen.

## Avaintermi: testitapaus (test case)

* Testitapaus on kokoelma syötteitä ja odotettuja vasteita (inputs ja outputs), jossa on yksi tai useampi vaihe.
* Testitapauksella on kohde, esimerkiksi metodi, luokka, ominaisuus, vaatimus tai käyttötapaus.
* Dynaamisessa testauksessa tietoa rakenteesta (valkolaatikko) tai toiminnallisuudesta (mustalaatikko) käytetään apuna testitapausten suunnittelussa ja toteutuksessa.
* Kun testitapauksia suunnitellaan, on tärkeää, että...
    * pidetään mielessä, että tulokset pitää tarkistaa (odotettu ja saatu tulos)
    * aloitetaan testitapauksilla, jotka kattavat todennäköisimmät tai useimmin esiintyvät käyttötapaukset ja
    * lisätään monimutkaisempia ja harvinaisempia testitapauksia, jotta testikattavuus paranee.
* Kun testitapausta ajetaan, testitapaus läpäisee testin vain, jos odotettu ja saatu tulos täsmäävät.

## Testitapausten suunnittelu ja kattavuus

* Testitapausten suunnittelu:
    * Hyvien testitapausten sunnittelun tavoite on:
        * että on tarpeeksi testitapauksia, jotta kaikki oleelliset tilanteet testataan
        * ja että ei ole turhia/ylimääräisiä (redundant) testitapauksia, joissa ei ole siis päällekkäisiyyttä
    * On useita tekniikoita, joilla johtaa (derive) testitapauksia: syklomaattinen kompleksisuus (cyclomatic complexity), ekvivalenssiluokat (equivalence classes), raja-arvo-analyysi (boundary value analysis), polku- tai tilanne-analyysi (path or scenario analysis) ja päätöstaulut (decision tables).
* Testitapausten kattavuus:
    * Päällekkäisyyden välttämiseksi, testitapausten kattavuus lasketaan
        * Kattavuus on mittari, joka kertoo kuinka suuri osa kohteesta on testattu valituilla testitapauksilla
    * Korkea kattavuus lisää luottamusta testauksen laatuun
        * Kattavuutta on monenlaista, esimerkiksi: lauseke- (statement), päätös-, haarautumis-, polku- ja tilanne (scenario)- kattavuus

## Komponenttitestaamisen kattavuudet

* Lausekekattavuus (statement coverage)
    * Kuinka suuren osan lausekkeista testitapaukset käyvät läpi. Yleisin käytetty kattavuus.
* Päätöskattavuus (decision coverage)
    * Kuinka suuren osan päätöksistä (branches) valitut testitapaukset käyvät läpi. Yhdistetään usein lausekekattavuuden kanssa.
* Kaikki-polut-kattavuus (All paths coverage)
    * Kuinka monta eri polkua komponentin läpi testitapaukset käyvät. Kattavuus on tehtävissä vain pienelle tai hyvin kriittisille tapauksille sillä polkujen määrä kasvaa nopeasti
* Itsenäisten polkujen kattavuus (independent paths coverage)
    * Kuinka paljon itsenäisistä poluista testitapaukset käyvät läpi. Hyvä kattavuus mutta käytetään harvoin. On hankala käytännössä määritellä itsenäiset polut käytännössä.

## Tekniikoita testitapausten tuottamiseksi komponenttitestaamista varten

* Määrityspohjainen (specification based)
    * Tätä tekniikkaa pitäisi aina käyttää
    * Määrityspohjaset testitapaukset käyvät läpi kaikki erilaiset määritetyt (defined) normaalit ja poikekukselliset tilanteet
    * Nämä tekniikat keskittyvät odotettuihin tilanteisiin, joten muitakin kannattaa käyttää täydennykseksi
* Raja-arvo- ja päätöspohjaiset (boundary value and decision based)
    * Usein syötteissä keskitytään raja-arvojen ympärille ja toistorakenteisiin ja päätöksiin
    * Tarkastellaan eri yhdistelmillä päätöksiä
* Ekvivalenssi-pohjaiset
    * Inputeja on yleensä lukematon määrä, joten syntyisi paljon päällekkäisyyttä testeissä. Päällekkäisyyttä voidaan vähentää käyttämällä ekvivalenssin osittamista (equivalence partitioning)
    * "Kaksi testiä kuuluvat samaan ekvivalenssi-luokkaan, jos niiden odotetaan antavan saman tuloksen (pass/fail). Useamman samaan ekvivalenssi-luokkaan kuuluvan testin testaaminen on päällekkäistä testaamista." (Cem Kaner)
* Syklomaattinen monimutkaisuus-pohjainen
    * Syklomaattinen monimutkaisuus tarkoittaa itsenäisten polkujen lukumäärää komponentin läpi.
    * Käytännössä: syklomaattinen monimutkaisuus=päätösten määrä + 1
    * Tämä voidaan tulkita testitapausten vähimmäismääräksi, jotta riittävä kattavuus saavutetaan

## Yksikkö- ja integrointi-testaaminen

* Yksikkötestaus (unit testing, module testing, component testing)
    * Yksiköiden testaaminen eristyksissä muista yksiköistä
    * Tehdään ennen kuin integroidaan muiden yksiköiden kanssa. Apuna käytetään "tynkiä" (stubs) ja malleja (mock-ups) integroinneista, jos tarpeen.
    * Tarkoitus on selvittää täyttääkö yksikkö sille asetetut vaatimukset
    * Tyypillisesti löytää virheet ohjelmoinnin logiikassa
* Integrointitestaaminen
    * Eri yksiköiden testaaminen yhdessä
    * Varmistetaan, että yksiköt oimivat yhdessä oikein
    * Testit voivat paljastaa epäsopivuudet rajapinnoissa (interfaces) tai sivuvaikutukset, joita voi syntyä yhteistoiminnassa
    * Jatkuva integrointi (continuous integration) ja kehitystyökalut ovat automatisoineet integrointitestejä

## Kattavuus ja tekniikoita testitapausten johtamiselle päästä-päähän-testaamista varten



## Sanastoa

* acceptance testing = hyväksymistestaus
* code review = koodin katselmointi
* error = virhe, erehdys, vika; tarkemmin: ihmisen teko, josta seuraa väärä lopputulos
* defect (bug, fault) = virhe, vika; tarkemmin: epätäydellisyys tai puuttellisuus tuotteessa, minkä takia vaatimuksia ja määrityksiä ei saavuteta 
* failure = epäonnistuminen, vika; tarkemmin: tapahtuma, jossa komponentti tai systeemi ei suoriudu halutusta toiminnosta
* quality assurance = laadunvarmistus
* system testing = systeemitestaus
* unit testing = yksikkötestaus
* validation = vahvistaminen, validointi, kelpuutus;
* verification = vahvistus, verifikaatio, tarkistus
