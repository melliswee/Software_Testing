# Ohjelmistotestaus

## Ohjelmien asennukset ja toiminnan testaaminen

Ohjelmien asennukset tehtiin kurssiohjeiden mukaisesti.

### Eclipse, JUnit ja shopping-list-app

Asensin uudemman Eclipsen tunnilla. Yritin aluksi päivittää nykyisen versioni, mutta en löytämieni ohjeiden avulla onnistunut siinä. Sen sijaan nimesin vanhan eclipse-nimisen kansion eclipse2-kansioksi, jonka jälkeen vain latasin uusimman Eclipse-version heidän verkkosivuiltaan, joka tallennettiin sitten eclipse-nimiseen kansioon. 

Käytän tehtävissä siis **Eclipsen Windows- versiota 22-06/R/** ([latauslinkki](https://ftp.snt.utwente.nl/pub/software/eclipse/technology/epp/downloads/release/2022-06/R/eclipse-jee-2022-06-R-win32-x86_64.zip)). 

Latasin shopping-list-webappin zip-kansiona ([GitHub](https://github.com/rkkauppi/shoppinglist)).

Käynnistin ostoslista-sovelluksen Eclipsessä, jolloin sovelluksen toimintaa pystyi tarkastelemaan osoitteesta "localhost:8080". Sovellus näytti tältä:

![app-running](/assets/asennukset/app_running.png)

Testasin perusominaisuuksia eli lisäsin uuden tuotteen ja sitten poistin sen. Ne toimivat odotusten mukaisesti käytettäessä selaimen kautta.

Projektissa oli valmiiksi testi, jossa testattiin tuotteen etsimistä. Ajoin JUnit-testit valitsemalla projektin päältä hiiren oikealla "Coverage As" --> JUnit Test, jolloin testit ajettiin. Tuloksena oli:

![test-coverage](/assets/asennukset/test_run1.png)

Tuloksesta voimme lukea, ettei testaus ole vielä kattavaa mutta ainakin JUnit-osuus toimi.

### python ja pip

Koneellani oli valmiiksi asennettuna:

* pip 19.0.3 - versio
* **Python 3.7.4** - versio 

Päivitin pip:n komentokehotteen antaessa kehotuksen päivityksestä.

> python -m pip install --upgrade pip

Nyt minulla on versio **pip 22.2.2**.

### Robotframework, Selenium library 6, Google Chrome, ChromeDriver

Asensin Robotframworkin komennolla:

> pip3 install robotframework

Asentuneen Robotframeworkin versio oli **robotframework-5.0.1**.

Tarkistin asennuksen komentokehotteessa:

> robot --version

Vastaukseksi sain: Robot Framework 5.0.1 (Python 3.7.4 on win32). Asennus onnistui.

Seuraavaksi asensin **Selenium library 6:n** komennolla:

> pip3 install robotframework-seleniumlibrary

Asennus meni läpi onnistuneesti.

**Googlen Chrome-selain** minulla oli jo valmiiksi asennettuna ja sen versio on: Versio 105.0.5195.127 (Virallinen koontiversio) (64-bittinen).

Koska minulla on Chromen pääversio 105, valitsin ladattavaksi ChromeDriverin version ChromeDriver 105.0.5195.52. 

Tallentteuani puretun kansion sisällön C-aseman käyttäjänimeni kansioon, ajoin komentokehotteessa komennon, joka asettaa chromedriverin PATH-muuttujaksi.

> setx path "%path%;C:\Users\melis\chromedriver"

Seuraavaksi tein ohjeiden mukaisen testin siitä toimiiko koko testausympäristö nyt. Latasin annetun projektin zip-tiedostona ja purin sen omaan kansioon. Siinä kansiossa annoin komennon:

> robot HelloRFTest.robot

Mutta testit epäonnistuivat:

![asennusten-testaus](/assets/asennukset/asennus_testaus.png)

Ensimmäinen virhe oli ettei chromedriveria löydy PATH:sta. Yrittäessäni löytää ratkaisua PATH- asiaan, törmäsin uuteen ongelmaan: komentokehote ei tunnista enää "python"-, "python3"-,"pip"-, "pip3"- ja "robot"- komentoja. En siis esimerkiksi saanut kysyttyä enää pythonin versiota. Huomasin lopulta, että "py"- komento edelleen toimii komentokehotteessa. En tiedä mikä ongelma lopulta oli, koska kun avasin komentokehotteen sijaan PowerShellin, kaikki nuo komennot toimivat. Minusta alkoi tuntua, että rikoin path-muuttujan käyttäjälle melis.

Hetken ihmeteltyäni tajusin, että nuo komennot toimivat sittenkin komentokehotteessa, joten en tiedä, mihin käytin edellisen tunnin tätä selvittäessä.

Lopulta keksin, miksi path ei toiminut: en ollut seurannut prikuulleen ohjetta. Olin asettanut chromedriverin suoraan melis-kansioon enkä kuten piti eli siten, että loin chromedriver-kansion sinne ja sitten purin siihen sen chromedriver-zipin.

Mutta testit eivät menneet silti läpi, mutta ainakin tuli eri tulos ja selain käynnistyi. Virhe oli, ettei chromea löytynyt:

![new_error1](/assets/asennukset/new_error_part1.png)

![new_error2](/assets/asennukset/new_error_part2.png)

![new_error3](/assets/asennukset/new_error_part3.png)

Etsin hetken tietoa ja ajattelin, että ehkä chrome oli asennettu johonkin outoon paikkaan, jos sitä ei kerran löytynyt. Mutta mielestäni Chrome oli oikeassa paikassa, joten päätin tehdä testit uudelleen. 

> robot HelloRFTest.robot

Ja kas, nyt ne menivätkin läpi:

![testit-toimii](/assets/asennukset/testit_toimii.png)

Taisin mennä aiemmalla kerralla koskemaan niihin evästenappuloihin ja suljin selaimen ehkä liian pian, jonka takia testit eivät menneet läpi aiemmin (?).

Mutta nyt voin todeta, että testausympäristö toimii tulevia koitoksia varten.

### ChromeRobot

Vielä olikin yksi asennus tehtävänä: ChromeRobot laajennus Chrome-selaimeen. Sen asentaminen tapahtui vain Chromen webstoresta [linkki](https://chrome.google.com/webstore/detail/chrome-robot/dihdbpkpgdkioobahfpnkondnekhbmlo).

Asentaminen onnistui ja sain DevToolseihin uuden välilehden "ChromeRobot":

![chromerobot](/assets/asennukset/chromerobot.png)
