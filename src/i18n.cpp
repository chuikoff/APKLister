// SPDX-License-Identifier: GPL-2.0-or-later
#include "i18n.h"
#include <cstring>
#include <unordered_map>

static thread_local Lang g_lang = Lang::En;
void set_lang(Lang l) { g_lang = l; }
Lang get_lang() { return g_lang; }

size_t u8len(const std::string& s) { size_t n = 0; for (unsigned char c : s) if ((c & 0xC0) != 0x80) n++; return n; }

bool parse_lang(const std::string& v, Lang& out) {
    std::string s; for (char c : v) if (c != ' ' && c != '\t' && c != '\r' && c != '\n') s += (char)(c >= 'A' && c <= 'Z' ? c + 32 : c);
    if (s == "ru" || s == "rus" || s == "russian") { out = Lang::Ru; return true; }
    if (s == "en" || s == "eng" || s == "english") { out = Lang::En; return true; }
    return false;
}

static const char* const kRu[][2] = {
    // ---- section titles
    {"FILE", "ФАЙЛ"}, {"PACKAGE", "ПАКЕТ"}, {"APEX", "APEX"}, {"APP BUNDLE", "APP BUNDLE (AAB)"},
    {"PERMISSIONS (%zu requested)", "РАЗРЕШЕНИЯ (запрошено: %zu)"}, {"FEATURES (%zu)", "ФУНКЦИИ УСТРОЙСТВА (%zu)"},
    {"APPLICATION META-DATA (%zu)", "МЕТАДАННЫЕ ПРИЛОЖЕНИЯ (%zu)"}, {"LIBRARIES (uses-library)", "БИБЛИОТЕКИ (uses-library)"},
    {"PACKAGE VISIBILITY (<queries>)", "ВИДИМОСТЬ ПАКЕТОВ (<queries>)"}, {"OTHER MANIFEST ELEMENTS", "ПРОЧИЕ ЭЛЕМЕНТЫ МАНИФЕСТА"},
    {"NATIVE LIBRARIES (%zu ABIs)", "НАТИВНЫЕ БИБЛИОТЕКИ (ABI: %zu)"}, {"DEX (%zu files)", "DEX (файлов: %zu)"},
    {"FRAMEWORKS & TECHNOLOGIES (heuristic)", "ФРЕЙМВОРКИ И ТЕХНОЛОГИИ (эвристика)"},
    {"BUILD INFO & BUNDLED LIBRARY VERSIONS", "СБОРКА И ВЕРСИИ ВСТРОЕННЫХ БИБЛИОТЕК"}, {"RESOURCES", "РЕСУРСЫ"},
    {"ZIP STRUCTURE", "СТРУКТУРА ZIP"}, {"CONTAINER ZIP STRUCTURE", "СТРУКТУРА ZIP КОНТЕЙНЕРА"},
    {"BASE APK ZIP STRUCTURE", "СТРУКТУРА ZIP БАЗОВОГО APK"}, {"BASE APK: %s", "БАЗОВЫЙ APK: %s"}, {"%s CONTAINER", "КОНТЕЙНЕР %s"},
    // ---- keys
    {"Path", "Путь"}, {"Type", "Тип"}, {"Size", "Размер"}, {"Name", "Имя"}, {"Version", "Версия"},
    {"Package name", "Имя пакета"}, {"Application label", "Название"}, {"Localized labels", "Локализованные названия"},
    {"Version name", "Версия"}, {"Version code", "Код версии"}, {"Architecture", "Архитектура"},
    {"Min SDK", "Мин. SDK"}, {"Target SDK", "Целевой SDK"}, {"Max SDK", "Макс. SDK"}, {"Compile SDK", "SDK компиляции"},
    {"Platform build version", "Версия платформы сборки"}, {"Install location", "Место установки"},
    {"Shared user ID", "Общий user ID"}, {"Shared user label", "Метка общего user ID"}, {"Split name", "Имя сплита"},
    {"Feature split", "Feature-сплит"}, {"Split required", "Требуются сплиты"}, {"Required split types", "Обязательные типы сплитов"},
    {"Split types", "Типы сплитов"}, {"Application class", "Класс Application"}, {"Icon", "Иконка"}, {"Round icon", "Круглая иконка"},
    {"Icon file used", "Файл иконки"}, {"Theme", "Тема"}, {"By protection class", "По уровню защиты"}, {"ABIs", "ABI"},
    {"16 KB page size", "Страницы 16 КБ"}, {"Total", "Итого"}, {"Compiler marker", "Маркер компилятора"},
    {"Flutter build", "Сборка Flutter"}, {"Kotlin modules", "Модули Kotlin"}, {"VCS info", "Информация VCS"},
    {"Resource table", "Таблица ресурсов"}, {"Package", "Пакет"}, {"Global string pool", "Глобальный пул строк"},
    {"Configurations", "Конфигурации"}, {"Types (entries)", "Типы (записей)"}, {"Locales", "Локали"}, {"Densities", "Плотности"},
    {"res/ files", "Файлы res/"}, {"Manifest XML", "XML манифеста"}, {"Entries", "Записей"},
    {"Compression methods", "Методы сжатия"}, {"Compressed total", "Всего сжато"}, {"Uncompressed total", "Всего без сжатия"},
    {"Central directory", "Центральный каталог"}, {"Archive comment", "Комментарий архива"},
    {"Encrypted entries", "Зашифрованных записей"}, {"Data descriptors", "Дескрипторы данных"}, {"UTF-8 name flag", "Флаг UTF-8 в именах"},
    {"Timestamps", "Даты файлов"}, {"zipalign (4-byte)", "zipalign (4 байта)"}, {"APK total", "Всего APK"},
    {"Modules", "Модули"}, {"Built by bundletool", "Собрано bundletool"}, {"Split dimensions", "Измерения сплитов"},
    {"Bundle metadata", "Метаданные бандла"}, {"Config", "Конфигурация"}, {"Native code", "Нативный код"},
    // ---- values
    {"yes", "да"}, {"no", "нет"}, {"optional", "необязательно"}, {"required", "обязательно"}, {"unknown", "неизвестно"},
    {"(not set)", "(не задано)"}, {"(not set; default %s)", "(не задано; по умолчанию %s)"},
    {"(not set; default internalOnly)", "(не задано; по умолчанию internalOnly)"},
    {"(default android.app.Application)", "(по умолчанию android.app.Application)"},
    {"(no <application> element)", "(нет элемента <application>)"},
    {"Other <application> attributes:", "Прочие атрибуты <application>:"}, {"Other <manifest> attributes:", "Прочие атрибуты <manifest>:"},
    {"Declared permissions (%zu):", "Объявленные разрешения (%zu):"}, {"(no attributes)", "(нет атрибутов)"},
    {"none (pure Java/Kotlin, or native code is in split APKs)", "нет (чистый Java/Kotlin либо нативный код в сплитах)"},
    {"%s: %zu files, %s", "%s: файлов %zu, %s"}, {"stored", "без сжатия"}, {"deflated", "deflate"},
    {"not an ELF file", "не ELF-файл"}, {"unreadable: ", "не читается: "}, {" (not 16KB-ready)", " (не готово к 16 КБ)"},
    {"NOT ready: %d of %d libraries have LOAD alignment < 16 KB", "НЕ готово: у %d из %d библиотек выравнивание LOAD < 16 КБ"},
    {"ready (all LOAD segments >= 16 KB aligned)", "готово (все сегменты LOAD выровнены на >= 16 КБ)"},
    {"no classes*.dex", "нет classes*.dex"}, {"File", "Файл"}, {"Ver", "Вер"}, {"Classes", "Классы"}, {"Methods", "Методы"},
    {"Fields", "Поля"}, {"Strings", "Строки"}, {"Types", "Типы"}, {"error: ", "ошибка: "}, {"not a DEX file", "не DEX-файл"},
    {"%s classes, %s methods, %s fields, %s strings, %s", "классов %s, методов %s, полей %s, строк %s, %s"},
    {"none found (dx / old D8, or marker stripped)", "не найден (dx / старый D8 или маркер удалён)"},
    {"(library/marker scan covered the first %s of DEX code)", "(поиск библиотек/маркеров охватил первые %s DEX-кода)"},
    {"Other code files (dynamic loading / packer?):", "Прочие файлы кода (динамическая загрузка / упаковщик?):"},
    {"nothing specific detected (plain Android/Java)", "ничего особенного не найдено (обычный Android/Java)"},
    {"Framework", "Фреймворк"}, {"Language", "Язык"}, {"Library", "Библиотека"}, {"Protector", "Защита"},
    {"%zu *.kotlin_module files", "файлов *.kotlin_module: %zu"}, {"no build metadata files found", "файлы с метаданными сборки не найдены"},
    {"Root *.properties (Play services / Firebase) (%zu):", "*.properties в корне (Play services / Firebase) (%zu):"},
    {"not present", "отсутствует"}, {"%s strings", "строк: %s"}, {"%s (%s values)", "%s (значений: %s)"}, {"(root)", "(корень)"},
    {"%zu files, %s", "файлов %zu, %s"}, {"binary, %d strings%s, resource map %d ids", "двоичный, строк %d%s, карта ресурсов %d id"},
    {"%zu (%zu directories)", "%zu (каталогов: %zu)"}, {"  (ratio %.1f%%)", "  (степень %.1f%%)"}, {"offset %llu, %s", "смещение %llu, %s"},
    {"%zu entries", "записей: %zu"}, {"  (fixed: reproducible AGP/bundletool build)", "  (фиксированные: воспроизводимая сборка AGP/bundletool)"},
    {"%zu of %zu stored entries NOT aligned", "%zu из %zu несжатых записей НЕ выровнены"}, {"all %zu stored entries aligned", "все несжатые записи (%zu) выровнены"},
    {"invalid JSON: ", "некорректный JSON: "}, {"%s (bundletool BuildApksResult)", "%s (bundletool BuildApksResult)"},
    {"APK files (%zu):", "APK-файлы (%zu):"}, {"base", "база"}, {"language", "язык"}, {"density", "плотность"}, {"config", "конфиг"},
    {"  <= analyzed below", "  <= разобран ниже"}, {"Other files:", "Прочие файлы:"}, {"  (OBB expansion file)", "  (OBB-файл расширения)"},
    {"ERROR: ", "ОШИБКА: "}, {"This ZIP archive contains neither AndroidManifest.xml nor .apk files.", "В этом ZIP-архиве нет ни AndroidManifest.xml, ни APK-файлов."},
    {"not an Android package", "не Android-пакет"}, {"cannot read: ", "не удаётся прочитать: "}, {"not a ZIP archive", "не ZIP-архив"},
    {"APK Lister %s, analysis took %lld ms", "APK Lister %s, анализ занял %lld мс"},
    {"\nERROR: out of memory while analyzing\n", "\nОШИБКА: не хватило памяти при анализе\n"},
    {"\nERROR: internal error while analyzing\n", "\nОШИБКА: внутренняя ошибка при анализе\n"},
    {"screen density", "плотность экрана"}, {"texture compression", "сжатие текстур"}, {"device tier", "класс устройства"},
    {"country set", "набор стран"}, {"unspecified", "не указано"}, {"no ", "без "},
    {"DANGEROUS", "ОПАСНОЕ"}, {"special access", "спец. доступ"}, {"signature/privileged", "подпись/системное"},
    {"normal", "обычное"}, {"other/custom", "прочее/своё"}, {"current development", "в разработке"},
    // ---- architecture
    {"64-bit ARM", "64-бит ARM"}, {"32-bit ARM", "32-бит ARM"}, {"32-bit ARM, ARMv5/v6, legacy", "32-бит ARM, ARMv5/v6, устаревшая"},
    {"64-bit x86", "64-бит x86"}, {"32-bit x86", "32-бит x86"}, {"64-bit RISC-V", "64-бит RISC-V"},
    {"64-bit MIPS, legacy", "64-бит MIPS, устаревшая"}, {"32-bit MIPS, legacy", "32-бит MIPS, устаревшая"},
    {"any (no native code)", "любая (нет нативного кода)"}, {"any", "любая"},
    {"   (incl. config splits)", "   (с учётом config-сплитов)"}, {"   (all modules)", "   (все модули)"},
    {"in config splits", "в config-сплитах"},
    {"unknown: base APK of a split app, native code (if any) is in config splits",
     "неизвестно: базовый APK split-приложения, нативный код (если есть) — в config-сплитах"},
    {" (legacy)", " (устар.)"}, {"64-bit: ", "64-бит: "}, {"32-bit: ", "32-бит: "}, {"other: ", "другие: "},
    {"   (+ .so outside lib/: %s)", "   (+ .so вне lib/: %s)"},
    {"%s (.so outside lib/, loaded by the app itself)", "%s (.so вне lib/, загружаются самим приложением)"},
    {"Architecture: %s", "Архитектура: %s"}, {"cannot open file: ", "не удаётся открыть файл: "},
};

const char* T(const char* en) {
    if (g_lang == Lang::En || !en) return en;
    static const std::unordered_map<std::string, const char*> m = [] {
        std::unordered_map<std::string, const char*> r;
        for (auto& p : kRu) r.emplace(p[0], p[1]);
        return r;
    }();
    auto it = m.find(en);
    return it == m.end() ? en : it->second;
}
std::string T(const std::string& en) { return g_lang == Lang::En ? en : std::string(T(en.c_str())); }
