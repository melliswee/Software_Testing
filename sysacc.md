# Ohjelmistotestaus - SYSACC- tehtävä

## A - tehtävä

### Tehtävänanto

"
Throughout this exercise, you will use Robot Framework from the Command Prompt. You will also view and edit Robot Framework test scripts. You can use any editor for this.

A) Consider the script HelloRFTest.robot you have already downloaded (from https://github.com/rkkauppi/softest-robotframework ), unzipped and run with Robot Framework if you did and checked the Robot Framework setup.
* Run the script again (robot HelloRFTest.robot in Command Prompt). What happens?
What is the result – does the test case pass or fail? What files are created?
* What does the test case test? What is its target?
* How does the test case determine whether the result is expected (pass) or not (fail)?
"

### Vastaus

HelloRFTest ajettiin uudelleen komennolla:

> robot HelloRFTest.robot

Testit (2 kpl) menivät läpi (PASS) ja kolme tiedostoa luotiin: output.xml, log.html ja report.html, joita voi tarkastella esimerkiksi avaamalla ne selaimessa. Testi oli Haaga-Helian etusivun aukaiseminen ja se kuului HelloRFTest- suiteen. 

![hellorf](/assets/sysacc/hellorf.png)

RF- kansion sisältö:

![dir](/assets/sysacc/dir_hello_rf.png)

Yhteenveto testisuitesta:

![report](/assets/sysacc/hello_report.png)

Testin vaiheet ja tilastotiedot annettiin log.html-tiedostossa:

![log](/assets/sysacc/hello_log.png)

Log-tiedosto sisälsi yksityiskohtia testin osasista ja tiedon, että testaamiseen käytettiin Selenium-kirjastoa:

![details](/assets/sysacc/test_exec_log.png)

Ensiksi avattiin Haaga-Helian etusivu (Seleniumin avulla), sitten testi pysäytettiin viideksi sekunniksi (BuiltIn), jonka jälkeen tarkistettiin, että avatulta sivulta löytyy sana "Etusivu" (Selenium-kirjastoa hyödyntäen) ja lopuksi vielä suljettiin selain (Selenium-kirjaston avulla). Testi menee läpi, kun kaikki nämä osat saadaan toteutettua. Minulle ei vielä kristallisoitunut, missä kohdassa ChromeDriver auttoi.

XML-tiedosto näytti tältä:

![xml](/assets/sysacc/hello_xml_log.png)

## B - tehtävä

### Tehtävänanto

"
For the remaining parts, you will to have the Shoppinglist App running (in Eclipse, src/main/java => package launch => Main.java, Run As… => Java Application.

B) Still consider the script HelloRFTest.robot.

* Edit the script so that it is a test script containing one test case that test that your local installation of the Shoppinglist App open at url localhost:8080.
* Rename the script to ShoppinglistTests.robot
* Rename the test case in the script to View Shoppinglist Test Case
"

### Vastaus



## C - tehtävä

### Tehtävänanto

"
C) Add test case Check Contents Test Case to check that shoppinglist has Milk,
Eggs and Bread. If necessary, edit the View Shoppinglist Test Case to not to close the browser so that Check Contents Test Case can continue without reopening the browser. Check Contents Test Case should close the browser.
"

### Vastaus