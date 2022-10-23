# Ohjelmistotestaus - UNIINT- tehtävä

## A - Tehtävänanto

"Unit and Integration Testing
Throughout this exercise, you will use the Shoppinglist App in Eclipse. <br>

A) Consider the class ShoppingListSearch already implemented and available in
src/test/java in package fi.haagahelia.course having a JUnit test case
testShoppingItemAdd.
* Run the test case (Run As... => JUnit test). What is the result – does the test case pass or
fail?
* What does the test case test? What is its target?
* How does the test case determine whether the result is expected (pass) or not (fail)?
* Run the test case so that its coverage is determined (Coverage As... => JUnit test. 
* What coverage is used? How do the coverage show in Eclipse?"

## A - Vastaukset

Valmiina ollut testi meni läpi JUnit-testinä.

![testi-lapi](/assets/testit/valmiina_tarjottu_testi.png)

Testissä luodaan ensiksi "feikkidao", jota luodessa siihen asetetaan jo muutama tuote (kuten testattu "Bread"). Testissä testataan onko lisäys toiminut. Ja se oli siis toiminut, koska "Bread" löytyi. Testi menee läpi silloin, kun odotettu leipä löytyy, jolloin assertThat=true.

Testasin testien kattavuuden jo aiemmin, kun testasin, että toimiiko JUnit ylipäätään:

![JUnit-toimi](/assets/asennukset/test_run1.png)

Koko testikattavuus oli 31,9% eli ei ollenkaan kattava. Kattavuus esitetään punaisina ja vihreinä prosenttiosuuspalkkeina.

## B - Tehtävänanto

Kuvakaappaus on tehtävänanto-ohjeesta otettu:

"<br>
B) Create a class ShoppingListAddRemove to src/test/java in package
fi.haagahelia.course and the two test cases in it as JUNit tests according to the following test plan:

![tehtavananto](/assets/testit/b_tehtavananto.png)
"

Tätä koodautehtävää tehdessä pääsin kertaamaan java-kieltä ja tekemän JUnit-testejä. Tehtävien tarkistuksen aikana opin, että toteutin omat ratkaisuni eri tavoin kuin malliratkaisut:

* Käytin listojen vertailua merkkijonojen vertailun ja if-else rakenteiden sijaan
* assertTrue- lausekkeita voi olla useampi kuin yksi, jolloin tietää helpommin, mikä osuus testin vaatimuksista epäonnistuu, esimerkiksi toisessa testissä vaatimuksena oli testata onko dao:ssa nyt vain leipä, jonka id pitää olla 1 --> sen sijaan, että kirjoittaisin "assertTrue(bothConditionsAreMet)", olisi kuvaavampaa kirjoittaa "assertTrue(idIsOne)" ja "assertTrue(TitleIsBread)" --> testejä ajaessa käy ilmi, että lisäyksen yhteydessä id:ksi ei tule se 1 vaan jotain muuta, jolloin testaaja olisi löytänyt bugin, joka ilmoitettaisiin devaajalle
* tunneilla sanottiin, että monesti get- ja set-metodien testaaminen on turhaa niiden yksinkertaisuuden takia
* huomio esimerkkinä käytetyn shopping-list-webappin ominaisuuksista
    * testeissä käytettiin FakeShoppingListDAO:ta, jossa tuotteen lisäys on toteutettu siten, että lisäävä osapuoli määrittelee annetun tuotenimekkeen id:n ja otsikon(dao.addItem(1, "Flour")) mutta näinhän ei kannata tehdä, sillä todellisuudessa tietokannan pitäisi pitää huoli id:n inkrementoinnista, jotta pääavaimen uniikkius säilyy varmasti eli lisäystoiminto voisi olla esimerkiksi vain (dao.addItem("Flour")), jonka jälkeen dao pitäisi huolen id:n asettamisesta
