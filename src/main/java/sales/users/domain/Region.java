package sales.users.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.persistence.*;
import java.util.List;

/**
 * Created by taras on 04.08.15.
 */
@Entity
@Table(name="regions")
public class Region {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @JsonProperty
    private Long id;

    @Column(name = "name", columnDefinition = "VARCHAR(50) UNIQUE")
    @JsonProperty
    private String name;

    @ManyToOne(targetEntity = Country.class)
    @JoinColumn(name = "country", referencedColumnName = "id")
    @JsonProperty
    private Country country;

    @OneToMany(mappedBy = "region")
    private List<City> cityList;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Country getCountry() {
        return country;
    }

    public void setCountry(Country country) {
        this.country = country;
    }
}
