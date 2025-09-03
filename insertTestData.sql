-- Vložení úrovní obtížnosti
INSERT INTO DIFFICULTY_LEVELS (id, level_name) VALUES
    (1, 'Lehká'),
    (2, 'Střední'),
    (3, 'Těžká');

-- Vložení týmů
INSERT INTO TEAMS (id, name, city, difficulty_level, password, last_cipher, penalty) VALUES
    (1, 'Rychlé šípy', 'Praha', 1, 'heslo1', 0, 0),
    (2, 'Vlčí smečka', 'Brno', 2, 'heslo2', 0, 10),
    (3, 'Orli', 'Ostrava', 3, 'heslo3', 1, 5);

-- Vložení pozic
INSERT INTO POSITIONS (id, gps, clue) VALUES
    (1, '50.087451,14.420671', 'Najdi sochu uprostřed náměstí.'),
    (2, '49.195061,16.606836', 'Podívej se pod lavičku.'),
    (3, '49.820923,18.262524', 'Hledej u velkého stromu.');

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
    (2, 2, 2, 2, 2, 'Hledej QR kód u stromu.'),
    (3, 3, 3, 3, 3, 'Gratulujeme, jsi v cíli!');

-- Vložení admina
INSERT INTO ADMINS (id, username, password) VALUES
    (1, 'admin', 'adminheslo');