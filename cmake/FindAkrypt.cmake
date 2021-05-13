# FindAkrypt.cmake
find_path(Akrypt_INCLUDE_DIR NAMES libakrypt.h)
# Найти требуемую библиотеку в системных путях. Префиксы/суффиксы (lib*,*.so,...) подставляются автоматически.
find_library(Akrypt_LIBRARY NAMES akrypt)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    Akrypt
    Akrypt_INCLUDE_DIR
    Akrypt_LIBRARY
)

if(Akrypt_FOUND AND NOT TARGET akrypt::akrypt)
    # Импортированная библиотека, т.е. не собираемая этой системой сборки.
    # Тип (статическая/динамическая) не известен – может быть любым, смотря что нашлось.
    add_library(akrypt::akrypt UNKNOWN IMPORTED)
    target_include_directories(akrypt::akrypt INTERFACE "${Akrypt_INCLUDE_DIR}")
    set_target_properties(akrypt::akrypt PROPERTIES
        # Указать имя файла собранной внешне библиотеки.
        IMPORTED_LOCATION "${Akrypt_LIBRARY}"
        # Указать язык библиотеки на случай, когда она статическая.
        IMPORTED_LINK_INTERFACE_LANGUAGES "C")
endif()

mark_as_advanced(Akrypt_INCLUDE_DIR Akrypt_LIBRARY)
 
