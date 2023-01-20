# Esimerkki testauksesta

Kuka tahansa voi testata. Oikeasti. Testaus ei ole taikaa eikä salatiedettä, vaan tiedon yhdistelyä. Joskus tiedon yhdistely on helppoa, jonkin tiedon osalta. Tarvittavaa tietoa laadusta ja sen puutteista on kuitenkin monenlaista, ja yhdistely vaatii aikaa *ulkoisen mielikuvituksen* eli testattavan sovelluksen äärellä.

Testaus on kuin täyttäisimme paperia, jonka teksti on kirjoitettu näkymättömällä musteella. Testausta tekevä ihminen, testaaja, ei riko sovellusta vaan käyttää sovellusta pyrkien paljastamaan että tavoitteemme jää tavoitellusta. Halu nähdä puutteita, ja avata niistä keskusteluja on oleellinen osa testausta. Kun koittaa osoittaa että sovellus ei toimi ja epäonnistuu parhaista yrityksistä huolimatta, voi luotettavammin olettaa että sovellus toimii.
Oma tiedon yhdistelytaitomme on tapa tuoda näkymätön muste näkyviin, sillä valmista listaa puutteista ei ole.

* * *

Aloittaessani kirjoittamaan tätä jo pitkään käynnissä ollutta ohjelmistotestauskirjaa toukokuussa 2012, kirjoitin varhaisen version tästä kappaleesta. Kotimaisen testauskentän lempilapsia oli VR:n silloin tuore lipunvarausjärjestelmä.

Testauksen lempilapseksi päätyi - ja päätyy edelleen - pääsemällä isosti otsikoihin laatupuutteiden vuoksi. Näin jälkikäteen asiaa perspektiivissä tarkastellen, otsikointien laatupuutteet varmasti maksoivat merkittäviä summia. Ne kuitenkin, vastoin alalla vallitsevaa ajatusta siitä että laatua ei testaamalla voi lisätä, korjattiin ulkoisesti tarkastellen hyvinkin selkeissä vaiheissa. Tiedettiinkö niistä julkaisuvaiheessa on ulkopuolelta vain spekulointia. Testauksen tulokset sisäisesti kun voivat johtaa myös päätökseen olla korjaamatta tai tietoisesti päätökseen korjata myöhemmin. Itseäni eniten harmitti eräs testausasiantuntija, joka ilmoittautui lausumaan huonosti testatusta järjestelmästä uutisiin ja unohti että **korjaamisen puute ei ole testauksen puute**. Jos emme tiedä, emme voi korjata. Mutta vaikka tietäisimme, voimme silti olla korjaamatta painavista syistä.

Minulla ei ole sisäpiirin tietoa VR:n silloisen testauksen ja korjauksen tasosta. Esimerkiksi testauksesta voi nostaa kuitenkin vuoden 2012 esimerkin VR:n websivuilta. Muistutan heti alkuunsa testauksen kultaisesta säännöstä: toisten tuotantopalvelimet eivät ole kenenkään testipalvelimia. Esimerkeissä ei mennä syvälle eikä erityisesti tehdä mitään ikävää joka voisi vaarantaa maksavien asiakkaiden palvelun toimivuuden. Pitäydyn testatessa kohteliaasti perusskenaarioissa.

* * *

Aloitetaan VR:n etusivulta, jonka vasemmasta laidasta löytyy junamatkan varaaminen. Testaajana lähden tutustumaan uuteen sovellukseen perustilanteella, jollaiseksi valitsen matkavarauksen Helsingistä Tampereelle kahden päivän kuluttua siten että olen perillä klo 12. Menoajankohta on sidottu sovittuun tapaamiseen, mutta palata voin hyvinkin joustavasti. Pääsivulla pääsen syöttämään lähtöpäivän, ja huomaan lähtöpäivän syötettyäni ruksin, että saankin kätevästi samalla varattua meno-paluulipun.

![Hae kotimaan matkaa 2012](image1.jpg)

Teen ensimmäisen havaintoni mahdollisesta puutteesta. Verkkokauppa tarjoaa minulle oletuksena tätä päivää paluulle, vaikka olen  päättänyt lähtöni olevan kahden päivän päästä. Havaintoni liittyy käyttäjän varauksen tekemisen helppouteen, ja vaikka vaihe käyttäjälle tuntuukin turhalta, täytän paluumatkan samalle illalle mahdollisimman myöhäiseen ajankohtaan. Kuittaan painaen Hae-painiketta ja pääsen hakutulossivulle.

![Hakutuloksia 2012](image1.jpg)

Huomaan suhteessa tavoitteeseeni, että luonnollisestikin etusivulla antamani aika tulkitaan lähtöaikana Helsingistä - toinen kirjattava havainto. Haluan kuitenkin pitäytyä taustoituksessani että minua kiinnostaa nimenomaan saapumisaika ja hetken ruutua tarkasteltuani huomaan että ainoa selkeä tapa siirtää ajankohtaa haluamallani tavalla on siirtyä edellisiin lähtöihin. Edellinen sivu -painike kuulostaa siltä että, siitä pääsen vain takaisin aloituspisteeseen. Painan kuitenkin sitä, toivoen että löydän jostakin monipuolisemman hakusivun.

![Paluu hakuun 2012](image3.jpg)

Odotetusta poiketen en päädy takaisin edelliselle sivulleni, vaan monipuolisempaan hakuun. Merkitsen kolmannen havaintoni kuitenkin todeten, että edelleen voin epäjohdonmukaisuuksista huolimatta jatkaa haluamani tilanteen läpikäyntiä. Huomaan ilahtuneena, että pääsen tästä näytöstä valitsemaan lähtöaika vs. saapumisaika, joka on testitilanteeni kantava teema. Ohimennen kiinnitän katseeni myös siihen, että päivämäärät ovat laatikoissaan aivan alareunassa, kun taas kohteet aikalailla keskitettynä - neljäs huomio. Vaihdan alasvetovalikosta aikavalinnalle määritteen saapumisaika, ja kuittaan Jatka-painikkeesta.

![Osta matka 2012](image4.jpg)

Tarkastelen hakutuloksia, ja huomaan niiden olevan edelleen siten että valitsemani aikaa ei tulkita saapumisaikana, vaan lähtöaikana. Kirjaan viidennen huomioni, joka selkeimmin toimii toisin kuin sovelluksen kuuluisi.

![Aikataulut 2012](image5.jpg)

Kirjaan myöhemmin testattavien asioideni listalle tehtävän hakusivulla olleista vaihtoehdoista aikataulun varauksen vs. matkan ostamisen vs. sarjalipulla matkustavan paikkavarauksen erillisyydestä testauskohteena sekä laajennetun haun mahdollisuudesta testauskohteena. Kirjaan omaksi tehtäväkseen myös aikataulujen esittelysivulla näytettyjen toiminnallisuuksien läpikäynnin, erityisesti tarkemmat tiedot kunkin matkavaihtoehdon osalta ja matkustusajankohdan vaihtamisen.

Juuri ennen kuin olen valmis julistamaan testaukseni tältä osin päättyneeksi, vilkaisen vielä taustalla ollutta konsoli-ikkunaa.

![Konsoli-ikkuna 2012](image6.jpg)

Totean konsoli-ikkunassa olevan varoituksia ja virheitä sivusta, jotka eivät normaalikäyttäjän silmin näy, mutta joiden osalta testauskursseilla opetetaan hyväksymistestaustakin tekeviä, että ne voivat paljastaa tarpeettomia asioita sisäiseen rakenteeseen liittyen ja olla uhka tietoturvamielessä. Kirjaan näistä tiedoista vielä kuudennen havaintoni.

Lopetan testaukseni todeten, että viiden minuutin testaukseen huomioita kirjaten on kulunut 50 minuuttia ja testaukseni kattavuus ei juurikaan ole ajankäyttöön suhteessa edennyt. Havaintoja sen sijaan on syntynyt ja niiden kirjaaminen vaatinut merkittävän osan testausajastani. Totean tämän olevan oleellinen tieto raportointiini, vain 5 minuuttia kattavuuden edistämiseen ja 45 minuuttia havaintoraporttien laatimiseen. Kokonaisuudelle ajateltu testausaika saattaa käydä vähiin, mikäli tämä trendi jatkuu läpi testaukseni.  Lisäksi totean, että ajankäytölleni onnekkaasti testasin varausketjun alkupäätä ja pääsin suoraan käyntiin, mikäli testaisin loppupäätä, ajankäytöstäni merkittävä osa olisi kulunut myös tilanteen alustamiseen. Tilanteen alustaminen on pakollista ja tärkeää, mutta kuluttaa merkittävän osan testausajasta viemättä kattavuutta suoraan eteenpäin.

 Jään vielä miettimään hetkeksi tulosteni aiheuttamaa reaktiota. Osa ei ole virheitä suhteessa siihen miten sivun on ajateltu toimivan, kaikki saattavat olla ennestään järjestelmän tekijöiden ja omistajien tiedossa. Testaus tuottaa tietoa, johon voi valita reagoivansa. Jos ei tiedä, ei voi tehdä valintaa. Ongelmat laadussa saattavat kertoa puutteellisesta testauksesta, mutta kokemus usein on että kyseessä on puutteellinen päätöksenteko korjausten osalta. Testaaminen ja korjaaminen ovat kaksi eri asiaa, vaikka toivoisinkin monesti niillä olevan erityisen suoraviivaisen yhteyden. Ja vaikka monesti puhutaankin siitä kuinka ohjelma rikkoutui testatessa, näin ei ole: se oli jo rikki, testauksen hommana on vain näyttää millä tapaa.

 * * *

Valitsemani testaustilanne havainnollistaa testauksen perustaitoja:

* on kyettävä tunnistamaan ongelmia (oraakkelit)
* on kyettävä pitämään kirjaa testauksen tavoitteesta (tarkoitus)
* on kyettävä arvioimaan etenemistä suhteessa tarvoiteltuun (kattavuus)
* on kyettävä raportoimaan havaintonsa selkeästi (havaintojen kirjaaminen)
* on kyettävä viestimään testauksen etenemisen ennusteesta suhteessa tavoiteltuun aikatauluun ja työmäärään (testausraportointi)
* on kyettävä laatimaan suunnitelmia testattavista asioista (testi-ideat)

Projektissa toimiessa, on lisäksi kyettävä jättämään materiaalia joka huolehtii testauksen toistamisesta muutoksen myötä (testitapaukset). Oma käsitykseni nykyaikaisen testauksen osalta on että se osa testitapauksista, joka kannattaa kirjoittaa ylös kannattaa kirjoittaa ylos ohjelmoituna testinä.

Kuten omassa työssäni koitan korostaa:

* Meillä on 1250 testiä, joiden ajaminen kestää 7 minuuttia.
* Ajamme ne keskimäärin 20 kertaa päivässä, eli 25 000 testiä päivässä.
* Näiden testien tekemä testaus on 10% siitä testauksesta mitä teemme. Muu testaus kasvattaa ja täydentää näitä testejä.

Tai toisessa projektissa:

* Meillä on 5000 muistiin kirjoitettua testitapausta, jotka eivät ole ohjelmoituja testejä.
* Jos ne lukee nopeasti läpi, töitä on 11 työpäivän verran pelkässä lukemisessa.
* Ei niitä kannata toistaa - tuotannossa olevaan sovellukseen tehdään pieniä hallittuja muutoksia
* Niissä on paljon vanhentunutta tietoa, joka piilottaa kaiken mahdollisesti hyödyllisen tiedon.

* * *

Kappaleessa käsitelty esimerkki on viiden minuutin testaus yhdelle perustilanteelle. Tuotannon erilaisten tilanteiden pikakelaus suhteessa mahdollisiin vaikutuksiin (riskit) vaatii enemmän kuin yhden perustilanteen.
