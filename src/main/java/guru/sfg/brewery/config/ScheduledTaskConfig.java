package guru.sfg.brewery.config;

import org.jetbrains.annotations.NotNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@EnableAsync
@Configuration
public class ScheduledTaskConfig {

    @Bean
    public @NotNull TaskExecutor taskExecutor() {
        return new SimpleAsyncTaskExecutor();
    }

}
