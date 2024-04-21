# MIREA slaves

```"Пывн есть вещь, распределенная справедливее всего"

Пывн Пывнов - 1337 г. до н. э.

nc 51.250.112.223 1737```

Бинарник представляет из себя функции для работы со структурами в куче.


``` ________________________________________________________________________
|    __  ___________  _________       _____ __    ___ _    _____________ |
|   /  |/  /  _/ __ \/ ____/   |     / ___// /   /   | |  / / ____/ ___/ |
|  / /|_/ // // /_/ / __/ / /| |     \__ \/ /   / /| | | / / __/  \__ \  |
| / /  / // // _, _/ /___/ ___ |    ___/ / /___/ ___ | |/ / /___ ___/ /  |
|/_/  /_/___/_/ |_/_____/_/  |_|   /____/_____/_/  |_|___/_____//____/   |
|________________________________________________________________________|

Hello, Director of MIREA!
Here you can see your students and whose slaves they are!

What can you do:

1. Print student
2. Print teacher
3. Print all students
4. Print all teachers
5. Add student
6. Add teacher
7. Link a student to a teacher by making him a slave
8. Delete student
9. Delete teacher
10. Allocate flag
11. Exit

Enter your choice: ```

Декомпиляция функций под номером 5 и 6:

```c
_QWORD *__fastcall createStudent(__int64 name) {
  _QWORD *result; // rax

  result = malloc(8uLL);
  *result = name;
  return result;
}

_QWORD *__fastcall createTeacher(__int64 name) {
  _QWORD *result; // [rsp+18h] [rbp-8h]

  result = malloc(0x18uLL);
  *result = name;               // [result]
  result[2] = malloc(0x50uLL);  // [result+0x10]
  *((_DWORD *)result + 2) = 0;  // [result+0x08]
  return result;
}```

Из декомпиляции можно вывести структуры, с которой идет работа:

```c
struct Student {  // size: 8
    char* name;
};


struct Teacher {   // size: 0x18
    char* name;
    int students_count;           // 0x8
    struct Student* students[9];  // 0x10
};```

Данные структуры хранятся в куче.
* Функция `2. Print teacher` (`printTeacher()`) выводит `char* name` структуры `Student`, которые хранятся в массиве `struct Student* students[9]` структуры `Teacher` указанной пользователем.
* Функция `7. Link a student to a teacher by making him a slave` (`linkStudentToTeacher()`) добавляет ссылку на указанный пользователем `Student` в массив `struct Student* students[9]` по индексу `int students_count` в структуре `Teacher`.
* Функция `8. Delete student` (`int deleteStudent()`) удаляет указанную пользователем структуру `Student`, в том числе освобождая переменную `char* name`.

Стоит заметить, что при вызове функции `int deleteStudent()` ссылка на удаляемую структуру `Student` не очищается из массива `struct Student* students[9]` стркутуры `Teacher`. Таким образом, даже после удаления структуры `Student` функция `printTeacher()` попытается вывести поле `char* name` в удаленной структуре.

Также есть функция `10. Allocate flag` (`createFlag()`), которая аллоцирует флаг согласно такой структуре:

```c
struct Flag {
    char* flag;
};```

Данная структура эквивалентна стркутре `Student`, где `char* flag` это `char* name`.

Факт того, что после удаления структуры `Student` новая структура будет аллоцированна его на месте, позволяет на месте `char* name` структуры `Student` написать `char* flag` структуры `Flag`.

Таким образом, последовательность эксплуатации будет такова:
1. 6 - создаем `Teacher`
2. 5 - создаем `Student`
3. 7 - добавляем ссылку на `Student` в массив `struct Student* students[9]` структуры `Teacher`.
4. 8 - удаляем структуру `Student`.
5. 10 - на его месте аллоцируем флаг.
6. 2 - выводим массив `struct Student* students[9]` структуры `Teacher`, получаем флаг вместо `char* name` структуры `Student`.
