# Tuloksellinen testaus

Edellisessä kappaleessa käsittelimme sitä mitä testaus on - laatutiedon keräämistä. Tässä kappaleessa keskitytään siihen kuka sitä tekee ja millä laajuudella, sekä siihen miten arvioidaan testauksen tuloksellisuutta.

* * * 

Jos siis testaus on jotain mikä on liian tärkeää jätettäväksi vain testaajille, ja toisaalta liian tärkeää jätettäväsi ilman testaajia, kuka sitä oikeastaan tekee, ja miltä osin? Tyypillinen jako on vähintään kolmiosainen:

* **Kehittäjät** testaavat mitä ovat toteuttaneet ja ympäristön josta se riippuu parhaan tietonsa ja taitonsa mukaan, löytäen monia virheitä joita erilliset testaajat eivät löytäisi. Kehittäjien tekemä perusteellinen testaus on kokonaistestauksen perusta, ja toistuva testaus ohjelmoiduilla testeillä on kehittäjien kotikenttää. Pienen mittakaavan testit ovat palautetta kehittäjiltä kehittäjille sekä suhteessa alkuperäisen tekijän tarkoitettuun toteutukseen ja sovelluksen toimintaan, kuin suhteessa sovelluksen tilaajan kanssa sovittuihin laatuominaisuuksiin. Tässä pätee ohjelmistokehityksen kansanviisaus: se mitä kehittäjä ymmärtää väärin tuppaa päätymään tuotantoon, ja jos laadulla ei ole väliä, toimituksen sisällöksi kelpaa ihan mitä tahansa.

* **Testaajat** testaavat täydentäen kehittäjän tuottamaa laatutietoa, etsien mahdollista tuloskuilua - missä odotukset asiakkaalla jäävät oman sisäisen tavoitteen ulkopuolelle. Testaajat yhdistelevät testaamista viettäen aikaa suoraan sovellusta tai sen mitä tahansa rajapintoja hyödyntäen, ja kirjoittaen sekä täydentäen ohjelmoituja testejä. Jos tiimi vetää linjoja sen osalta mitä ohjelmoiduista testeistä tekevät kehittäjät ja mitä testaajat, tyypillinen jako on että kehittäjät tekevät pieniä testejä, joiden kattavuutta voidaan arvioida suhteessa koodiin ajamalla kattavuustyökaluja, kun taas testaajat tekevät keskisuuria ja suuria testejä jotka simuloivat erilaisia käyttäjiä ja käyttävät käyttäjille suunnattuja rajapintoja. Testaajat ovat myös yleensä vastuussa testausympäristön ylläpidosta, ja testausympäristö on usein testaajien kotikenttää.

* **Asiakkaat** testaavat sovellusta käyttäessään sitä, myös vahingossa, mutta erityisesti tarkoituksella erilaisissa hyväksymistestauksissa. Asiakkaat ja käyttäjät, sovellusalueen syväluotaavat asiantuntijat, huomaavat usein monipuolisen käytön yhteydessä toiminnallisuutta tai ominaisuuksia, joihin muut eivät ole kiinnittäneet huomiota vaikka ko. toiminnallisuutta olisikin aiemmin testattu. Asiakkaita ja käyttäjiä on ohjelmistokehityksessä usein ketjussa siten että mitä tahansa rakensimme hyödynnämme jonkun toisen aiemmin rakentamia sovelluskehikoita ja kirjastoja, ja olemme näille itse asiakasroolissa tekemässä hyväksymistestausta.

Mikäli jokin asiaa jää testaamatta, se ei tarkoita ettei se toimisi. Sen sijaan se tarkoittaa että se voi toimia tai siinä voi olla erilaisia puutteita. Testaus on aina riskipohjaista - valitaan niitä asioita joiden täytyy välttämättä toimia ja tarkistetaan niitä eri osapuolien toimesta mieluummin vaikka pariinkin kertaan. Usein hyvin toimiva sääntö on että mikäli osaamme kuvitella ongelman jota emme kuitenkaan halua korjata, ei sen testaamiseen välttämättä myöskään kannata käyttää aikaa. Tietämisen arvo on linkitettynä korjaamisen mahdollisuuteen, tai ainakin siihen että osataan kertoa miten ja miksi kyseistä asiaa ei ole haluttu korjata.

* * *

![Tuloskuilu - kuilun koko vaihtelee](tuloskuilu.png)
