# Router-Simulation

<h5>Calcan Elena-Claudia <br/>
321CA</h5>

  Programul reprezinta procesul de dirijare a pachetelor a router-ului. <bt>
  Procesul de dirijare consta in primirea unui pachet, investigarea tabelei
  de rutare, descoperirea rutei corespunzatoare si dirijarea pachetului. <br>
  Protocoalele utilizate sunt urmatoarele: <br>
	    • Ethernet <br>
	    • ARP <br>
	    • IP <br>
	    • ICMP <br>

  • rutele sunt date ca input si salvate intr-un vector, fiecare element
	avand informatii despre: prefix, next hop, masca si interfata <br>
	• vectorul a fost sortat dupa prefix si masca, folosind functia predefinita 
	in C, qsort() <br>
	• tabela arp se retine intr-un vector care se actualizeaza atunci cand se efectueaza
	o cerere de tip ARP REPLAY <br>
	• de fiecare data cand se primeste un pachet se extrage header-ul de ethernet
	si se verifica tipul urmatorului protocol, ARP sau IP <br><br>

### 1. Protocolul ARP
-------------------------------------------------------------------------------
	
  • se extrage header-ul de arp din pachet <br>
	• se verifica cererea pe care a facut-o sender-ul <br>

	a. ARP REQUEST
   
  • are rolul de a afla adresa MAC a host-ului cu adresa IP destinatie <br>
	• daca este destinat router-ului, acesta va trimite un ARP REPLAY cu adresa
	MAC potrivita <br>
	• inainte de a trimite pachetul se actualizeaza header-ul de ethernet astfel:
	adresa sender-ului devine adresa destinatie, iar MAC-ul gasit devine adresa sursa <br>
	• se actualizeaza header-ul de ARP <br>

	b. ARP REPLAY
   
  • este actualizata tabela ARP cu IP-ul si adresa MAC primita <br>
	• se trimit pachetele din coada <br><br>

### 2. Protocoalele IP si ICMP
-------------------------------------------------------------------------------

  • se extrage header-ul de IP, urmat de cel de ICMP <br>
	• daca pachetul este destinat router-ului si este de tip ICMP ECHO REQUEST,
	atunci va transmite un mesaj ICMP ECHO REPLAY si se arunca pachetul <br>
	• daca ttl-ul este mai mic sau egal ca 1, atunci se transmite un mesaj ICMP
	TIME EXCEEDED si se arunca pachetul <br>
	• se verifica integritatea pachetului; daca valoarea checksum-ului vechi este
	diferita de noua valoare, atunci pachetul a fost corupt si se arunca <br>
	• se actualizeaza header-ul de IP prin decrementarea ttl-ului si recalcularea
	checksum-ului <br>
	• se interogheaza tabela de rutare pentru a sti drumul cel mai bun prin care
	se trimite pachetul <br>
	• pentru interogarea tabelei de rutare s-a folosit algoritmul de Binary Search <br>
	• daca nu exita drum, atunci se trimite un mesaj ICMP DESTINATION UNREACHABLE 
	si se arunca pachetul <br>
	• cand s-a aflat next hop-ul, se interogheaza tabela ARP <br>
	• daca nu se cunoaste adresa MAC a next hop-ului, atunci pachetul se salveaza
	intr-o coada si se creeaza un ARP REQUEST care este trimis ca broadcast <br>
	• altfel, daca stim adresa MAC, se actualizeaza header-ul de ethernet si se 
	trimite pachetul <br>
  
