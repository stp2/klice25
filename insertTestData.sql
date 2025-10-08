-- Vložení úrovní obtížnosti
INSERT INTO DIFFICULTY_LEVELS (id, level_name) VALUES
    (1, 'Lehká'),
    (2, 'Střední'),
    (3, 'Těžká');

-- Vložení týmů: heslo1, heslo2, heslo3
INSERT INTO TEAMS (id, name, city, difficulty_level, password, last_cipher, penalty) VALUES
    (1, 'Rychlé šípy', 'Praha', 1, '4bc2ef0648cdf275032c83bb1e87dd554d47f4be293670042212c8a01cc2ccbe', 0, 0),
    (2, 'Vlčí smečka', 'Brno', 2, '274efeaa827a33d7e35be9a82cd6150b7caf98f379a4252aa1afce45664dcbe1', 0, 10),
    (3, 'Orli', 'Ostrava', 3, '05af533c6614544a704c4cf51a45be5c10ff19bd10b7aa1dfe47efc0fd059ede', 1, 5);

-- Vložení pozic
INSERT INTO POSITIONS (id, gps, clue) VALUES
    (1, '50.087451,14.420671', 'Najdi sochu uprostřed náměstí.'),
    (2, '49.195061,16.606836', 'Podívej se pod lavičku.'),
    (3, '49.820923,18.262524', 'Hledej u velkého stromu.'),
    (4, '50.075538,14.437800', 'Kousek od fontány.');

-- Vložení QR kódů
INSERT INTO QR_CODES (id, position_id, uid) VALUES
    (1, 1, 'QR123ABC'),
    (2, 2, 'QR456DEF'),
    (3, 3, 'QR789GHI');

-- Vložení šifer
INSERT INTO CIPHERS (id, assignment, solution, clue) VALUES
    (1, 'Rozlušti morseovku: ... --- ...', 'SOS', 'Použij tabulku morseovky.'),
    (2, 'Najdi slovo v osmisměrce: KÓD', 'KÓD', 'Začni v levém horním rohu.'),
    (3, 'Přelož do češtiny: HELLO', 'AHOJ', 'Použij slovník.');

-- Vložení úkolů
INSERT INTO TASKS (id, cipher_id, position_id, difficulty_level, order_num, end_clue) VALUES
    (1, 1, 1, 1, 1, 'Pokračuj k dalšímu stanovišti.'),
    (2, 2, 2, 2, 1, 'Hledej QR kód u stromu.'),
    (3, 3, 3, 3, 1, 'Gratulujeme, jsi v cíli!'),
    (4, 1, 4, 1, 2, 'To je vše, děkujeme za účast!');

-- Vložení admin: heslo
INSERT INTO ADMINS (id, username, password) VALUES
    (1, 'admin', '56b1db8133d9eb398aabd376f07bf8ab5fc584ea0b8bd6a1770200cb613ca005');