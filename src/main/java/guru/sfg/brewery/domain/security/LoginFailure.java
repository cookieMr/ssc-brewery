package guru.sfg.brewery.domain.security;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.jetbrains.annotations.Nullable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import java.sql.Timestamp;
import java.util.Optional;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class LoginFailure {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer id;

    private String username;

    @ManyToOne
    private User user;

    private String sourceIp;

    @CreationTimestamp
    @Column(updatable = false)
    private Timestamp createdDate;

    @UpdateTimestamp
    private Timestamp lastModifiedDate;

    public void setCreatedDate(@Nullable Timestamp createdDate) {
        this.createdDate = Optional.ofNullable(createdDate)
                .map(Timestamp::clone)
                .map(Timestamp.class::cast)
                .orElse(null);
    }

    public @Nullable Timestamp getCreatedDate() {
        return Optional.ofNullable(createdDate)
                .map(Timestamp::clone)
                .map(Timestamp.class::cast)
                .orElse(null);
    }

    public void setLastModifiedDate(@Nullable Timestamp lastModifiedDate) {
        this.lastModifiedDate = Optional.ofNullable(lastModifiedDate)
                .map(Timestamp::clone)
                .map(Timestamp.class::cast)
                .orElse(null);
    }

    public @Nullable Timestamp getLastModifiedDate() {
        return Optional.ofNullable(lastModifiedDate)
                .map(Timestamp::clone)
                .map(Timestamp.class::cast)
                .orElse(null);
    }

}
