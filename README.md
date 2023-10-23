# logging-messages
Осуществление логирования происходит через класс Logger, который содержит методы для записи и чтения строк из файла лога. 
Данный класс также использует std::shared_mutex для обеспечения безопасности при доступе к файлу из многопоточной среды.
Вот как логирование осуществляется:
При создании экземпляра Logger открывается указанный файл (или создается новый, если такового не существует), на который указывает поле logfile.

Logger(const std::string& filename){
    logfile.open(filename, std::fstream::in | std::fstream::out | std::fstream::app);
    if(!logfile) throw std::runtime_error("Unable to open the log file!");
}

Метод write_line используется для записи строки в файл лога. 
Элемент std::lock_guard используется для блокировки мьютекса на время выполнения операции записи, чтобы другие потоки не могли одновременно записывать в файл.

void write_line(const std::string& log_line){
    std::unique_lock<std::shared_mutex> lock(mtx);
    logfile << log_line << std::endl;
}

Метод read_line используется для чтения следующей строки из файла лога. 
Мьютекс блокируется с помощью std::shared_lock, что позволяет другим потокам, также использующим std::shared_lock, читать из файла в то же время.
Однако, это ограничивает любую запись в файл до тех пор, пока блокировка на чтение не будет снята.
std::string read_line(){
    std::shared_lock<std::shared_mutex> lock(mtx);
    std::string line;
    std::getline(logfile, line);
    return line;
}
Logger используется в функциях process_registration и process_login для записи результата регистрации или входа в файл лога.
Он также используется в функции run_server для записи информации о новом соединении.

logger.write_line(std::string(msg.username) + " registration failed");
logger.write_line("Accepted connection from: " + std::string(clientIP));

В конце жизненного цикла Logger, в деструкторе проводится закрытие файла лога, освобождая все связанные ресурсы.
~Logger(){
    if(logfile.is_open()){
       logfile.close();
   }
}
