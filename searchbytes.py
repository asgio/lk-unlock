#!/usr/bin/env python3
"""
Универсальный поиск по hex-шаблону с wildcard '*'
Пример использования: python sig_search.py файл.bin "2*48784402f08*f*29460346**46204600f0**fa8*46afe7"
"""

import sys
import os
import re


def parse_pattern(pattern_str: str) -> list:
    """
    Парсит hex-строку с wildcard в список условий

    Правила:
    - Каждая пара символов = один байт
    - '**' = любой байт целиком
    - '8*' = старший ниббл 8, младший любой
    - '*8' = младший ниббл 8, старший любой
    - 'FF' = точное значение байта
    - 'F*' = точный старший ниббл F
    - '*F' = точный младший ниббл F

    Возвращает список кортежей: (тип_проверки, значение)
    типы: 'exact', 'any', 'high', 'low'
    """
    # Очищаем строку от пробелов и переводим в верхний регистр
    pattern_str = pattern_str.replace(' ', '').replace('\t', '').upper()

    if len(pattern_str) % 2 != 0:
        raise ValueError(f"Длина шаблона должна быть чётной (сейчас {len(pattern_str)} символов)")

    pattern = []

    for i in range(0, len(pattern_str), 2):
        byte_str = pattern_str[i:i+2]

        if byte_str == '**':
            # Полностью любой байт
            pattern.append(('any', None))

        elif byte_str[0] == '*' and byte_str[1] == '*':
            pattern.append(('any', None))

        elif byte_str[0] == '*' and byte_str[1] != '*':
            # Только младший ниббл задан: *F
            try:
                low_nibble = int(byte_str[1], 16)
            except ValueError:
                raise ValueError(f"Неверный символ в шаблоне: '{byte_str}' на позиции {i}")
            pattern.append(('low', low_nibble))

        elif byte_str[0] != '*' and byte_str[1] == '*':
            # Только старший ниббл задан: F*
            try:
                high_nibble = int(byte_str[0], 16)
            except ValueError:
                raise ValueError(f"Неверный символ в шаблоне: '{byte_str}' на позиции {i}")
            pattern.append(('high', high_nibble))

        else:
            # Точное значение байта: FF
            try:
                exact_value = int(byte_str, 16)
            except ValueError:
                raise ValueError(f"Неверный символ в шаблоне: '{byte_str}' на позиции {i}")
            pattern.append(('exact', exact_value))

    return pattern


def check_byte(data_byte: int, condition: tuple) -> bool:
    """
    Проверяет один байт данных на соответствие условию

    Args:
        data_byte: байт из данных
        condition: кортеж (тип, значение) из parse_pattern()

    Returns:
        True если байт соответствует условию
    """
    cond_type, cond_value = condition

    if cond_type == 'any':
        return True

    elif cond_type == 'exact':
        return data_byte == cond_value

    elif cond_type == 'high':
        # Проверяем только старший ниббл
        return (data_byte >> 4) == cond_value

    elif cond_type == 'low':
        # Проверяем только младший ниббл
        return (data_byte & 0x0F) == cond_value

    return False


def search_pattern(data: bytes, pattern: list, start_offset: int = 0) -> list[int]:
    """
    Ищет все вхождения шаблона в данных

    Args:
        data: бинарные данные
        pattern: список условий из parse_pattern()
        start_offset: начальное смещение для поиска

    Returns:
        Список смещений, где найден шаблон
    """
    if not pattern:
        return []

    pattern_len = len(pattern)
    results = []

    # Используем первый не-'any' байт для быстрого поиска
    fast_byte_index = None
    fast_byte_value = None

    for i, (cond_type, cond_value) in enumerate(pattern):
        if cond_type == 'exact':
            fast_byte_index = i
            fast_byte_value = cond_value
            break
        elif cond_type == 'high':
            # Можем использовать для предварительного фильтра,
            # но проще найти точный байт
            continue

    pos = start_offset

    while pos < len(data) - pattern_len + 1:
        # Если нашли точный байт для быстрого поиска, используем его
        if fast_byte_index is not None:
            # Ищем следующий точный байт
            search_pos = data.find(bytes([fast_byte_value]), pos)
            if search_pos == -1:
                break

            # Вычисляем позицию начала шаблона
            start_pos = search_pos - fast_byte_index

            if start_pos < 0:
                pos = search_pos + 1
                continue

            # Проверяем весь шаблон с этой позиции
            if start_pos + pattern_len <= len(data):
                match = True
                for i, condition in enumerate(pattern):
                    if not check_byte(data[start_pos + i], condition):
                        match = False
                        break

                if match:
                    results.append(start_pos)

            pos = search_pos + 1
        else:
            # Нет точных байт, проверяем каждый
            match = True
            for i, condition in enumerate(pattern):
                if not check_byte(data[pos + i], condition):
                    match = False
                    break

            if match:
                results.append(pos)

            pos += 1

    return results


def format_hex_dump(data: bytes, offset: int, length: int, highlight_pattern: list = None) -> str:
    """
    Форматирует hex-дамп с подсветкой найденного шаблона
    """
    result = []
    result.append(f"Смещение: 0x{offset:08X}\n")
    result.append(f"Байты: ")

    for i in range(min(length, len(data) - offset)):
        if i > 0 and i % 16 == 0:
            result.append("\n       ")
        elif i > 0 and i % 8 == 0:
            result.append(" ")

        byte_val = data[offset + i]

        # Проверяем, является ли байт частью шаблона
        if highlight_pattern and i < len(highlight_pattern):
            cond = highlight_pattern[i]
            if cond[0] == 'any':
                result.append(f"\033[90m{byte_val:02X}\033[0m ")  # серый для wildcard
            elif cond[0] == 'high' or cond[0] == 'low':
                result.append(f"\033[93m{byte_val:02X}\033[0m ")  # жёлтый для нибблов
            else:
                result.append(f"\033[92m{byte_val:02X}\033[0m ")  # зелёный для точных
        else:
            result.append(f"{byte_val:02X} ")

    result.append("\n")
    return ''.join(result)


def print_match_context(data: bytes, offset: int, pattern: list, context_bytes: int = 32):
    """
    Выводит контекст вокруг найденного совпадения
    """
    pattern_len = len(pattern)
    start_ctx = max(0, offset - context_bytes)
    end_ctx = min(len(data), offset + pattern_len + context_bytes)

    print(f"{'='*70}")
    print(f"Найдено совпадение по смещению: 0x{offset:08X} (десятичное: {offset})")
    print(f"{'='*70}")

    # Выводим hex-дамп с контекстом
    for addr in range(start_ctx, end_ctx, 16):
        # Адрес
        line = f"0x{addr:08X} | "

        # Hex байты
        hex_part = []
        ascii_part = []

        for i in range(16):
            if addr + i < len(data):
                byte_val = data[addr + i]

                # Определяем, является ли байт частью шаблона
                in_pattern = offset <= addr + i < offset + pattern_len

                if in_pattern:
                    hex_part.append(f"\033[92m{byte_val:02X}\033[0m")
                elif addr + i < offset or addr + i >= offset + pattern_len:
                    hex_part.append(f"{byte_val:02X}")
                else:
                    hex_part.append(f"{byte_val:02X}")

                # ASCII часть
                if 32 <= byte_val <= 126:
                    ascii_part.append(chr(byte_val))
                else:
                    ascii_part.append('.')
            else:
                hex_part.append('  ')
                ascii_part.append(' ')

        line += ' '.join(hex_part)
        line += '  |' + ''.join(ascii_part) + '|'
        print(line)

    print()


def save_results(filename: str, results: list[int], pattern_str: str):
    """
    Сохраняет результаты поиска в файл
    """
    output_file = filename + ".matches.txt"
    with open(output_file, 'w') as f:
        f.write(f"Поиск шаблона: {pattern_str}\n")
        f.write(f"Найдено совпадений: {len(results)}\n")
        f.write("=" * 60 + "\n")
        for i, offset in enumerate(results, 1):
            f.write(f"{i:4d}. Смещение: 0x{offset:08X} ({offset})\n")

    print(f"\nРезультаты сохранены в: {output_file}")


def main():
    if len(sys.argv) < 3:
        print("Универсальный поиск по hex-шаблону с wildcard")
        print()
        print("Использование:")
        print(f"  {sys.argv[0]} <файл> <шаблон> [опции]")
        print()
        print("Синтаксис шаблона:")
        print("  FF     - точное значение байта (hex)")
        print("  **     - любой байт целиком")
        print("  F*     - точный старший ниббл (F), любой младший")
        print("  *F     - точный младший ниббл (F), любой старший")
        print()
        print("Примеры:")
        print(f"  {sys.argv[0]} program.bin \"DEADBEEF\"")
        print(f"  {sys.argv[0]} program.bin \"2*48784402f08*f*29460346\"")
        print(f"  {sys.argv[0]} program.bin \"**48**\"")
        print(f"  {sys.argv[0]} program.bin \"f*f*f*f*\"")
        print()
        print("Опции:")
        print("  -c N     показать N байт контекста вокруг каждого совпадения (по умолчанию 32)")
        print("  -a       показать все совпадения (по умолчанию первые 10)")
        print("  -s       сохранить результаты в файл")
        sys.exit(1)

    filename = sys.argv[1]
    pattern_str = sys.argv[2]

    # Парсинг опций
    context_size = 32
    show_all = False
    save = False

    for i in range(3, len(sys.argv)):
        if sys.argv[i] == '-c' and i + 1 < len(sys.argv):
            context_size = int(sys.argv[i + 1])
        elif sys.argv[i] == '-a':
            show_all = True
        elif sys.argv[i] == '-s':
            save = True

    # Проверяем существование файла
    if not os.path.exists(filename):
        print(f"Ошибка: файл '{filename}' не найден")
        sys.exit(1)

    # Загружаем файл
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Ошибка при чтении файла: {e}")
        sys.exit(1)

    print(f"Файл: {filename}")
    print(f"Размер: {len(data):,} байт (0x{len(data):X})")
    print(f"Шаблон: {pattern_str}")
    print()

    # Парсим шаблон
    try:
        pattern = parse_pattern(pattern_str)
    except ValueError as e:
        print(f"Ошибка в шаблоне: {e}")
        sys.exit(1)

    print(f"Размер шаблона: {len(pattern)} байт")
    print(f"Структура шаблона:")

    # Показываем структуру шаблона
    for i, (cond_type, cond_value) in enumerate(pattern):
        if cond_type == 'any':
            print(f"  Байт {i:2d}: ** (любой)")
        elif cond_type == 'exact':
            print(f"  Байт {i:2d}: {cond_value:02X} (точное значение)")
        elif cond_type == 'high':
            print(f"  Байт {i:2d}: {cond_value:X}* (старший ниббл)")
        elif cond_type == 'low':
            print(f"  Байт {i:2d}: *{cond_value:X} (младший ниббл)")

    print()
    print("Поиск...")

    # Ищем шаблон
    results = search_pattern(data, pattern)

    print(f"Найдено совпадений: {len(results)}")
    print()

    # Показываем результаты
    max_show = len(results) if show_all else min(10, len(results))

    for i in range(max_show):
        print_match_context(data, results[i], pattern, context_size)

    if not show_all and len(results) > 10:
        print(f"... и ещё {len(results) - 10} совпадений")
        print("Используйте опцию -a для показа всех результатов")

    # Сохраняем если нужно
    if save:
        save_results(filename, results, pattern_str)


if __name__ == "__main__":
    # Поддержка цвета в Windows
    if sys.platform == 'win32':
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

    main()
